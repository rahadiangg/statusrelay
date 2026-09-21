package alibaba

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/incident/httpx"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

// DefaultBaseURL is the international status API.
const DefaultBaseURL = "https://status.alibabacloud.com/api/status"

// Source implements incident.Source against the Alibaba status API.
type Source struct {
	id     string
	client *client
	log    *slog.Logger
	clock  clock.Clock

	userAgent   string
	regionCodes []string
	regionNames []string
	preferLang  string

	mu          sync.Mutex
	catalogue   *Catalogue
	catalogueAt time.Time
	selfCheckOK bool
	learned     learnedEvent
	// details caches hydrated history rows by id. Open rows are never cached:
	// their lastUpdateTime may be null, and a cache keyed on a value that
	// never changes would miss every progress update on exactly the records
	// that matter.
	details map[string]cachedDetail
}

// learnedEvent is the newest resolved event ever seen, used as the known-good
// probe for the self-check so pruned history degrades the check rather than
// breaking it.
type learnedEvent struct {
	ID       string
	RegionID string
	Start    time.Time
	End      time.Time
}

type cachedDetail struct {
	lastUpdate msTime
	ev         wireEvent
}

// Option configures a Source.
type Option func(*Source)

func WithLogger(l *slog.Logger) Option { return func(s *Source) { s.log = l } }
func WithClock(c clock.Clock) Option   { return func(s *Source) { s.clock = c } }
func WithRegions(c, n []string) Option {
	return func(s *Source) { s.regionCodes, s.regionNames = c, n }
}

// WithPreferLang sets the Accept-Language sent upstream. The server localises
// product and region names from it; titles are English regardless.
func WithPreferLang(lang string) Option { return func(s *Source) { s.preferLang = lang } }

// WithUserAgent sets the User-Agent sent upstream. Ignored when WithHTTPClient
// supplies the transport.
func WithUserAgent(ua string) Option { return func(s *Source) { s.userAgent = ua } }

// WithHTTPClient replaces the HTTP layer. Primarily for tests.
//
// The caller then owns the fixed headers: the catalogue endpoint refuses
// requests without Referer, and names come back in Chinese without
// Accept-Language. Build the client with httpx.WithHeader for both.
func WithHTTPClient(d doer) Option { return func(s *Source) { s.client.http = d } }

// New builds a Source. id is the instance name, base is the API URL.
func New(id, base string, opts ...Option) (*Source, error) {
	if strings.TrimSpace(base) == "" {
		base = DefaultBaseURL
	}
	s := &Source{
		id:         id,
		client:     &client{base: base},
		log:        slog.Default(),
		clock:      clock.System{},
		preferLang: "en",
		details:    make(map[string]cachedDetail),
	}
	// Start optimistic; the poller runs SelfCheck at startup and on its own
	// cadence, and a failure there flips this for every later snapshot.
	s.selfCheckOK = true
	for _, o := range opts {
		o(s)
	}
	if s.client.http == nil {
		hopts := []httpx.Option{
			httpx.WithHeader("Accept-Language", s.preferLang),
			httpx.WithHeader("Referer", Referer),
		}
		if s.userAgent != "" {
			hopts = append(hopts, httpx.WithUserAgent(s.userAgent))
		}
		s.client.http = httpx.New(hopts...)
	}
	return s, nil
}

func (s *Source) ID() string   { return s.id }
func (s *Source) Kind() string { return "alibaba" }

func (s *Source) Capabilities() incident.Capabilities {
	return incident.Capabilities{
		// endTime exists and is read, but which list a record appears in is
		// what decides its status; the field only corroborates.
		HasExplicitStatus:      true,
		HasUpdateTimestamp:     true,
		ResolutionIsStructural: true,
		SupportsHistoryWindow:  false,
		SupportsPostMortem:     false,
	}
}

// Fetch returns the provider's whole current view.
//
// The open list failing is fatal: a snapshot that says "nothing is open"
// because the request failed is the worst lie this service can tell. The
// history list failing degrades the snapshot to incomplete instead, and so
// does any detail lookup that comes back empty — the list said the record
// exists, so an empty detail is a fact about the API, not about the incident.
func (s *Source) Fetch(ctx context.Context) (*incident.Snapshot, error) {
	now := s.clock.Now()
	m := &mapper{sourceID: s.id}

	openWire, openTotal, err := s.client.inProgress(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching open incidents: %w", err)
	}

	snap := &incident.Snapshot{
		SourceID:        s.id,
		FetchedAt:       now,
		UnresolvedCount: openTotal,
		Complete:        true,
	}
	warn := func(kind, detail string) {
		snap.Complete = false
		snap.Warnings = append(snap.Warnings, incident.Warning{Kind: kind, Detail: detail})
	}

	for i := range openWire {
		s.hydrate(ctx, &openWire[i], false, warn)
	}
	snap.Open = m.mapEvents(openWire, incident.StatusOpen)
	if openTotal != len(openWire) {
		// The count and the list come from the same response, so this is a
		// weaker oracle than a separate endpoint would be; it still catches
		// pagination being applied to the open list without our asking.
		warn(incident.AnomalyCountMismatch,
			fmt.Sprintf("vendor reports %d open, the list held %d", openTotal, len(openWire)))
	}

	histWire, histTotal, herr := s.client.history(ctx, 1, historyPageSize)
	if herr != nil {
		warn("history_unavailable", herr.Error())
		s.log.Warn("resolved-incident list unavailable; snapshot is incomplete", "source", s.id, "err", herr)
	} else {
		if histTotal < len(histWire) {
			warn(incident.AnomalyCountMismatch,
				fmt.Sprintf("vendor reports %d historical, the page held %d", histTotal, len(histWire)))
		} else if histTotal > len(histWire) {
			s.log.Debug("history has more rows than one page", "source", s.id, "total", histTotal, "page", len(histWire))
		}
		fresh := make(map[string]cachedDetail, len(histWire))
		for i := range histWire {
			s.hydrate(ctx, &histWire[i], true, warn)
			fresh[histWire[i].ID.String()] = cachedDetail{lastUpdate: histWire[i].LastUpdateTime, ev: histWire[i]}
		}
		s.mu.Lock()
		s.details = fresh // ids that left the page leave the cache; bounded by page size
		s.mu.Unlock()

		snap.Recent = m.mapEvents(histWire, incident.StatusResolved)
		s.learn(snap.Recent)
	}

	openIDs := make(map[string]bool, len(snap.Open))
	for _, r := range snap.Open {
		openIDs[r.Key.ProviderID] = true
	}
	for _, r := range snap.Recent {
		if openIDs[r.Key.ProviderID] {
			// Both kept: the diff lets the open list win, and the warning is
			// how anyone learns the vendor is publishing the same id twice.
			snap.Warnings = append(snap.Warnings, incident.Warning{
				Kind: incident.AnomalyDuplicateID, Detail: "event " + r.Key.ProviderID + " is listed both open and resolved"})
		}
	}

	s.mu.Lock()
	selfOK := s.selfCheckOK
	s.mu.Unlock()
	if !selfOK {
		snap.Complete = false
	}

	snap.Warnings = append(snap.Warnings, m.anomalies...)
	return snap, nil
}

// hydrate replaces an abbreviated list row with its full detail record.
//
// A cache hit (history rows only, same lastUpdateTime) costs no request. A
// detail that cannot be had leaves the row abbreviated — title, severity and
// times are still real — with no scope and Global false: "we failed to look"
// is not "the vendor published no region", and the filter routes a scopeless
// record through include_global anyway, so the page still goes out.
func (s *Source) hydrate(ctx context.Context, w *wireEvent, cacheable bool, warn func(kind, detail string)) {
	id := w.ID.String()
	if cacheable {
		s.mu.Lock()
		c, ok := s.details[id]
		s.mu.Unlock()
		if ok && c.lastUpdate.Set == w.LastUpdateTime.Set && c.lastUpdate.T.Equal(w.LastUpdateTime.T) {
			*w = c.ev
			return
		}
	}
	full, found, err := s.client.detail(ctx, id)
	switch {
	case err != nil:
		warn("detail_unavailable", "event "+id+": "+err.Error())
		s.log.Warn("incident detail unavailable; record is abbreviated", "source", s.id, "event", id, "err", err)
		return
	case !found:
		warn("detail_unavailable", "event "+id+" is listed but its detail returned no record")
		return
	}
	// The list row is the fresher witness for the two fields both carry.
	if !full.EndTime.Set && w.EndTime.Set {
		full.EndTime = w.EndTime
	}
	if !full.LastUpdateTime.Set && w.LastUpdateTime.Set {
		full.LastUpdateTime = w.LastUpdateTime
	}
	*w = full
}

// learn records the newest resolved event that names a region, so the
// self-check has a known-good probe that survives history being pruned.
func (s *Source) learn(recs []incident.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range recs {
		if r.StartedAt.IsZero() || len(r.Scope) == 0 {
			continue
		}
		if r.StartedAt.After(s.learned.Start) {
			s.learned = learnedEvent{ID: r.Key.ProviderID, RegionID: r.Scope[0].RegionCode, Start: r.StartedAt, End: r.EndedAt}
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

	zs, err := s.client.zones(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching the region catalogue: %w", err)
	}
	c := buildCatalogue(zs)
	if err := c.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.catalogue, s.catalogueAt = c, s.clock.Now()
	s.mu.Unlock()
	return c, nil
}

// ValidateRegions reconciles the configured regions against the live
// catalogue. A mismatch is fatal at startup; an unreachable catalogue is not,
// so the watcher can be restarted during the outage it exists to report.
func (s *Source) ValidateRegions(ctx context.Context) error {
	c, err := s.Catalogue(ctx, time.Hour)
	if err != nil {
		return err
	}
	return c.ReconcileRegions(s.regionCodes, s.regionNames)
}

var _ incident.Source = (*Source)(nil)
