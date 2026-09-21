package tencent

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

// DefaultBaseURL is the international dashboard. There is no path-prefix
// dataset selector and no known mirror.
const DefaultBaseURL = "https://status.tencentcloud.com"

// progressWindow bounds which resolved records still get their timeline
// fetched. Open records always do; a record resolved within this window does
// too, so the resolving update is captured. Older ones are quiet history and
// not worth a request per poll.
const progressWindow = 7 * 24 * time.Hour

// Source implements incident.Source against the Tencent Cloud dashboard API.
type Source struct {
	id     string
	client *client
	log    *slog.Logger
	clock  clock.Clock

	regionCodes []string
	regionNames []string

	mu           sync.Mutex
	catalogue    *Catalogue
	catalogueAt  time.Time
	selfCheckOK  bool
	learnedEvent learnedEvent
}

// learnedEvent is the newest event we have ever seen, used as the known-good
// probe for the self-check so a pruned seed degrades the check instead of
// breaking it.
type learnedEvent struct {
	Code string
	At   time.Time
}

// Option configures a Source.
type Option func(*Source)

func WithLogger(l *slog.Logger) Option { return func(s *Source) { s.log = l } }
func WithClock(c clock.Clock) Option   { return func(s *Source) { s.clock = c } }
func WithRegions(c, n []string) Option {
	return func(s *Source) { s.regionCodes, s.regionNames = c, n }
}

// WithHTTPClient replaces the HTTP layer. Primarily for tests.
func WithHTTPClient(d doer) Option { return func(s *Source) { s.client.http = d } }

// New builds a Source. id is the instance name, base is the dashboard URL.
func New(id, base string, opts ...Option) (*Source, error) {
	if strings.TrimSpace(base) == "" {
		base = DefaultBaseURL
	}
	s := &Source{
		id:     id,
		client: &client{base: base, http: httpx.New()},
		log:    slog.Default(),
		clock:  clock.System{},
		// Optimistic until the poller's first SelfCheck says otherwise.
		selfCheckOK: true,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func (s *Source) ID() string   { return s.id }
func (s *Source) Kind() string { return "tencent" }

func (s *Source) Capabilities() incident.Capabilities {
	return incident.Capabilities{
		HasExplicitStatus:      true,
		HasUpdateTimestamp:     true,
		ResolutionIsStructural: false,
		SupportsHistoryWindow:  true,
		SupportsPostMortem:     false,
		MaxHistoryLookback:     time.Duration(lookbackMons) * 30 * 24 * time.Hour,
	}
}

// Fetch returns the provider's whole current view.
//
// One list carries both open and resolved records, so a failed list is fatal:
// there is no partial truth to report. The timeline and region calls that
// follow only enrich or cross-check it, and each degrades on its own.
func (s *Source) Fetch(ctx context.Context) (*incident.Snapshot, error) {
	now := s.clock.Now()
	m := &mapper{sourceID: s.id, now: now}

	rows, truncated, err := s.client.historyEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching events: %w", err)
	}
	open, resolved := m.mapEvents(rows)

	snap := &incident.Snapshot{
		SourceID:        s.id,
		FetchedAt:       now,
		Open:            open,
		Recent:          resolved,
		UnresolvedCount: -1, // no independent count endpoint exists
		Complete:        true,
	}
	if truncated {
		snap.Complete = false
		snap.Warnings = append(snap.Warnings, incident.Warning{
			Kind:   "history_truncated",
			Detail: fmt.Sprintf("read %d rows before the page walk stopped", len(rows)),
		})
	}
	if m.unkeyed > 0 {
		snap.Complete = false
	}
	s.learn(resolved, open)

	s.attachProgress(ctx, snap, m, now)
	s.crossCheckRegions(ctx, snap)

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

// attachProgress fetches timelines for the records that can still change.
//
// A failed or empty timeline never costs the record: the row itself is the
// evidence, the timeline is detail. It is warned because an empty list for a
// known code is exactly what the API returns for an unknown one, so a run of
// them means the endpoint has moved.
func (s *Source) attachProgress(ctx context.Context, snap *incident.Snapshot, m *mapper, now time.Time) {
	fill := func(recs []incident.Record, want func(incident.Record) bool) {
		for i := range recs {
			r := &recs[i]
			if !want(*r) {
				continue
			}
			ps, err := s.client.progress(ctx, r.Key.ProviderID)
			if err != nil {
				snap.Warnings = append(snap.Warnings, incident.Warning{
					Kind:   "progress_unavailable",
					Detail: r.Key.ProviderID + ": " + err.Error(),
				})
				continue
			}
			if len(ps) == 0 {
				snap.Warnings = append(snap.Warnings, incident.Warning{
					Kind:   "progress_unavailable",
					Detail: r.Key.ProviderID + ": timeline is empty",
				})
				continue
			}
			r.Updates = m.mapProgress(r.Key.ProviderID, ps)
			r.FP = incident.Compute(*r)
		}
	}
	fill(snap.Open, func(incident.Record) bool { return true })
	fill(snap.Recent, func(r incident.Record) bool {
		return !r.EndedAt.IsZero() && now.Sub(r.EndedAt) <= progressWindow
	})
}

// crossCheckRegions compares the list against the vendor's own per-region
// flag, which comes from a different code path.
//
// A region flagged EventsIn that no open record covers means the list is
// missing something, and absence from it proves nothing: the snapshot is
// incomplete. The reverse (an open record in a region not flagged) is only
// warned; it is the vendor's flag lagging, not our list lying.
func (s *Source) crossCheckRegions(ctx context.Context, snap *incident.Snapshot) {
	c, err := s.refreshCatalogue(ctx)
	if err != nil {
		snap.Complete = false
		snap.Warnings = append(snap.Warnings, incident.Warning{
			Kind:   "regions_unavailable",
			Detail: err.Error(),
		})
		s.log.Warn("region flags unavailable; snapshot is incomplete", "source", s.id, "err", err)
		return
	}

	// A Global record covers the vendor's non-regional pseudo-region, which
	// is where the mapper dropped it from.
	covered := make(map[string]bool)
	for _, r := range snap.Open {
		if r.Global {
			covered[globalRegion] = true
		}
		for _, sc := range r.Scope {
			covered[sc.RegionCode] = true
		}
	}
	for _, code := range sortedKeys(c.EventsIn) {
		switch flagged := c.EventsIn[code]; {
		case flagged && !covered[code]:
			snap.Complete = false
			snap.Warnings = append(snap.Warnings, incident.Warning{
				Kind:   incident.AnomalyCountMismatch,
				Detail: "vendor flags an event in " + code + " but the list holds none there",
			})
		case !flagged && covered[code]:
			snap.Warnings = append(snap.Warnings, incident.Warning{
				Kind:   incident.AnomalyCountMismatch,
				Detail: "the list holds an open event in " + code + " but the vendor flags none there",
			})
		}
	}
}

// sortedKeys keeps warning order stable across polls of identical data.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// learn records the newest event seen so the self-check has a known-good
// probe that survives the seed being pruned.
func (s *Source) learn(lists ...[]incident.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, recs := range lists {
		for _, r := range recs {
			if !r.StartedAt.IsZero() && r.StartedAt.After(s.learnedEvent.At) {
				s.learnedEvent = learnedEvent{Code: r.Key.ProviderID, At: r.StartedAt}
			}
		}
	}
}

// refreshCatalogue always hits the network: the EventsIn flags are live state
// and must be as fresh as the list they are checked against.
func (s *Source) refreshCatalogue(ctx context.Context) (*Catalogue, error) {
	w, err := s.client.regions(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching regions: %w", err)
	}
	c := buildCatalogue(w)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.catalogue, s.catalogueAt = c, s.clock.Now()
	s.mu.Unlock()
	return c, nil
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
	return s.refreshCatalogue(ctx)
}

// ValidateRegions reconciles the configured regions against the live
// catalogue. Unreachable-catalogue errors must not be fatal at startup, or
// the watcher cannot be restarted during the outage it exists to report.
func (s *Source) ValidateRegions(ctx context.Context) error {
	c, err := s.Catalogue(ctx, time.Hour)
	if err != nil {
		return err
	}
	return c.ReconcileRegions(s.regionCodes, s.regionNames)
}

var _ incident.Source = (*Source)(nil)
