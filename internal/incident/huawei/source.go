package huawei

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

// DefaultBaseURL is the international dataset.
//
// The trailing path segment is load-bearing: without it the same host serves
// the mainland dataset at HTTP 200, with different event ids and different
// regions, and nothing downstream can tell the difference.
const DefaultBaseURL = "https://status.service.huaweicloud.com/intl"

// DefaultMirrorURL serves byte-identical data from a different edge, which is
// what makes it useful when the primary is blocked rather than broken.
const DefaultMirrorURL = "https://status.service.huaweicloud.cn/intl"

// Source implements incident.Source against the Huawei status API.
type Source struct {
	id     string
	client *client
	mapper func() *mapper
	log    *slog.Logger
	clock  clock.Clock

	allowNonIntl bool
	userAgent    string
	regionCodes  []string
	regionNames  []string
	preferLang   string
	levels       map[int64]incident.Severity

	mu           sync.Mutex
	catalogue    *Catalogue
	catalogueAt  time.Time
	selfCheckOK  bool
	learnedEvent learnedWindow
}

// learnedWindow is the newest event we have ever seen, used as the known-good
// probe for the self-check.
//
// It is learned rather than hardcoded on purpose: pinning a specific event id
// forever means the probe starts failing the day the vendor prunes history, and
// a check that cries wolf is a check somebody switches off.
type learnedWindow struct {
	ID string
	At time.Time
}

// Option configures a Source.
type Option func(*Source)

func WithMirror(u string) Option       { return func(s *Source) { s.client.mirror = u } }
func WithLogger(l *slog.Logger) Option { return func(s *Source) { s.log = l } }
func WithClock(c clock.Clock) Option   { return func(s *Source) { s.clock = c } }
func WithRegions(c, n []string) Option {
	return func(s *Source) { s.regionCodes, s.regionNames = c, n }
}
func WithPreferLang(lang string) Option { return func(s *Source) { s.preferLang = lang } }

// WithAllowNonIntl permits a dataset that is predominantly mainland regions.
// Only set this when watching the mainland site deliberately; it disables the
// guard against a base URL that lost its path prefix.
func WithAllowNonIntl(v bool) Option { return func(s *Source) { s.allowNonIntl = v } }

// WithLevelMap overrides the severity mapping. Levels absent from the map grade
// as Unknown and still alert.
func WithLevelMap(m map[int64]incident.Severity) Option {
	return func(s *Source) { s.levels = m }
}

// WithHTTPClient replaces the HTTP layer. Primarily for tests.
func WithHTTPClient(d doer) Option { return func(s *Source) { s.client.http = d } }

// WithUserAgent sets the User-Agent sent upstream. Ignored when WithHTTPClient
// supplies the transport. Without it every release identifies as statwatch/dev,
// which is useless to whoever reads the upstream's access log when deciding
// what to block.
func WithUserAgent(ua string) Option { return func(s *Source) { s.userAgent = ua } }

// New builds a Source. id is the instance name, base is the dataset URL.
func New(id, base string, opts ...Option) (*Source, error) {
	if strings.TrimSpace(base) == "" {
		base = DefaultBaseURL
	}
	s := &Source{
		id:     id,
		client: &client{base: base},
		log:    slog.Default(),
		clock:  clock.System{},
	}
	s.preferLang = "en"
	s.levels = defaultLevels()
	// Start optimistic. A source that has not yet been self-checked is not
	// thereby suspect; the poller runs SelfCheck at startup and on its own
	// cadence, and a failure there flips this for every later snapshot.
	s.selfCheckOK = true
	for _, o := range opts {
		o(s)
	}
	if s.client.http == nil {
		var hopts []httpx.Option
		if s.userAgent != "" {
			hopts = append(hopts, httpx.WithUserAgent(s.userAgent))
		}
		s.client.http = httpx.New(hopts...)
	}
	s.mapper = func() *mapper {
		return &mapper{sourceID: s.id, preferLang: s.preferLang, levels: s.levels}
	}
	return s, nil
}

func (s *Source) ID() string   { return s.id }
func (s *Source) Kind() string { return "huawei" }

func (s *Source) Capabilities() incident.Capabilities {
	return incident.Capabilities{
		// There is no status field anywhere in this API. Resolution is inferred
		// purely from which list a record appears in.
		HasExplicitStatus: false,
		// A record mtime exists only for already-resolved records, which is
		// exactly the set that needs change detection least.
		HasUpdateTimestamp:     false,
		ResolutionIsStructural: true,
		SupportsHistoryWindow:  true,
		SupportsPostMortem:     true,
		MaxHistoryLookback:     0, // no observed floor
	}
}

// Fetch returns the provider's whole current view.
//
// The two lists are fetched separately because the API has no single endpoint
// that returns both, and their failure modes differ:
//
//   - current-events failing is fatal. Without it we know nothing about what is
//     open, and returning a snapshot that says "nothing is open" would be a
//     lie with the worst possible consequence.
//   - past-events failing is NOT fatal, but it makes the snapshot incomplete:
//     without the resolved list we cannot distinguish "this incident resolved"
//     from "we simply did not see it this time".
func (s *Source) Fetch(ctx context.Context) (*incident.Snapshot, error) {
	now := s.clock.Now()
	m := s.mapper()

	currentWire, _, err := s.client.currentEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching open incidents: %w", err)
	}

	snap := &incident.Snapshot{
		SourceID:        s.id,
		FetchedAt:       now,
		Open:            m.mapEvents(currentWire, incident.StatusOpen),
		UnresolvedCount: -1,
		Complete:        true,
	}

	pastWire, _, perr := s.client.pastEvents(ctx)
	if perr != nil {
		// Degrade rather than fail: an open incident we can still see is worth
		// reporting even when the resolved list is unavailable.
		snap.Complete = false
		snap.Warnings = append(snap.Warnings, incident.Warning{
			Kind:   "past_events_unavailable",
			Detail: perr.Error(),
		})
		s.log.Warn("resolved-incident list unavailable; snapshot is incomplete",
			"source", s.id, "err", perr)
	} else {
		snap.Recent = m.mapEvents(pastWire, incident.StatusResolved)
		s.learn(snap.Recent)
	}

	if stat, serr := s.client.statistic(ctx); serr == nil {
		snap.UnresolvedCount = stat.Unresolved
		// A free consistency oracle from a different code path. It is the check
		// that catches "current-events returned an empty array because a query
		// parameter was silently ignored".
		if stat.Unresolved != len(snap.Open) {
			snap.Complete = false
			snap.Warnings = append(snap.Warnings, incident.Warning{
				Kind: incident.AnomalyCountMismatch,
				Detail: fmt.Sprintf("vendor reports %d unresolved, the list held %d",
					stat.Unresolved, len(snap.Open)),
			})
		}
		if perr == nil && stat.History < len(snap.Recent) {
			snap.Complete = false
			snap.Warnings = append(snap.Warnings, incident.Warning{
				Kind: incident.AnomalyCountMismatch,
				Detail: fmt.Sprintf("vendor reports %d historical, the list held %d",
					stat.History, len(snap.Recent)),
			})
		}
	}

	s.mu.Lock()
	selfOK := s.selfCheckOK
	s.mu.Unlock()
	if !selfOK {
		// A source that has failed its own integrity check cannot vouch for
		// absence, whatever the individual requests returned.
		snap.Complete = false
	}

	snap.Warnings = append(snap.Warnings, m.anomalies...)
	return snap, nil
}

// learn records the newest event seen so the self-check has a known-good window
// that survives history being pruned.
func (s *Source) learn(recs []incident.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range recs {
		if r.StartedAt.IsZero() {
			continue
		}
		if r.StartedAt.After(s.learnedEvent.At) {
			s.learnedEvent = learnedWindow{ID: r.Key.ProviderID, At: r.StartedAt}
		}
	}
}

// Catalogue returns the cached region inventory, refreshing it when stale.
func (s *Source) Catalogue(ctx context.Context, maxAge time.Duration) (*Catalogue, error) {
	s.mu.Lock()
	if s.catalogue != nil && s.clock.Now().Sub(s.catalogueAt) < maxAge {
		c := s.catalogue
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	rows, err := s.client.services(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching the service catalogue: %w", err)
	}
	c := buildCatalogue(rows)
	if err := c.Validate(s.allowNonIntl); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.catalogue, s.catalogueAt = c, s.clock.Now()
	s.mu.Unlock()
	return c, nil
}

// ValidateRegions reconciles the configured regions against the live catalogue.
//
// Callers should treat a failure as fatal at startup but must NOT treat an
// inability to reach the catalogue as fatal: refusing to start when the vendor
// is unreachable would mean the watcher cannot be restarted during exactly the
// outage it exists to report.
func (s *Source) ValidateRegions(ctx context.Context) error {
	c, err := s.Catalogue(ctx, time.Hour)
	if err != nil {
		return err
	}
	return c.ReconcileRegions(s.regionCodes, s.regionNames)
}

var _ incident.Source = (*Source)(nil)
