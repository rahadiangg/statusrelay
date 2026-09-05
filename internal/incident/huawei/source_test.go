package huawei

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

var testEpoch = time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)

// routes maps a URL path suffix to a fixture file. A request to an unmapped
// path is a test failure, not a 404: it means production code reached for an
// endpoint the test did not expect.
type routes map[string]string

// fakeSHD serves fixtures and records every URL requested, so tests can assert
// on the query parameters production code actually sent.
type fakeSHD struct {
	srv  *httptest.Server
	mu   sync.Mutex
	urls []string
}

func newFakeSHD(t *testing.T, r routes) *fakeSHD {
	t.Helper()
	f := &fakeSHD{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		f.urls = append(f.urls, req.URL.String())
		f.mu.Unlock()

		// The real API rejects a malformed start_time with HTTP 400 and a
		// specific error code. The self-check depends on that behaviour, so the
		// fake has to model it rather than serving the window fixture blindly.
		if strings.HasSuffix(req.URL.Path, pathHistoryEvents) {
			if st := req.URL.Query().Get("start_time"); st != "" && !validStartTime(st) {
				body, _ := os.ReadFile(filepath.Join("testdata", "error_400_bad_parameter.json"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(body)
				return
			}
		}

		for suffix, fixture := range r {
			if !strings.HasSuffix(req.URL.Path, suffix) {
				continue
			}
			body, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Errorf("reading fixture %s: %v", fixture, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if strings.HasSuffix(fixture, ".json") {
				w.Header().Set("Content-Type", "application/json")
			} else {
				w.Header().Set("Content-Type", "text/html")
			}
			if strings.Contains(fixture, "error_400") {
				w.WriteHeader(http.StatusBadRequest)
			} else if strings.Contains(fixture, "error_500") {
				w.WriteHeader(http.StatusInternalServerError)
			}
			_, _ = w.Write(body)
			return
		}
		t.Errorf("unexpected request to %s", req.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// base returns a URL carrying a path prefix, mirroring production, so tests
// prove the prefix survives every join.
// validStartTime mirrors the upstream's strict acceptance: seconds precision,
// Z suffix. Milliseconds, numeric offsets and date-only values are all rejected.
func validStartTime(s string) bool {
	_, err := time.Parse("2006-01-02T15:04:05Z", s)
	return err == nil
}

func (f *fakeSHD) base() string { return f.srv.URL + "/intl" }

func (f *fakeSHD) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.urls))
	copy(out, f.urls)
	return out
}

// healthyRoutes is the everything-is-fine fixture set.
func healthyRoutes() routes {
	return routes{
		pathCurrentEvents: "current-events_empty.json",
		pathPastEvents:    "past-events_event13.json",
		pathStatistic:     "event-statistic_ok.json",
		pathServices:      "services_full.json",
		pathHistoryEvents: "history-events_window.json",
	}
}

func newTestSource(t *testing.T, f *fakeSHD, opts ...Option) *Source {
	t.Helper()
	base := append([]Option{
		WithHTTPClient(httpx.New(httpx.WithRetries(0), httpx.WithBackoff(0))),
		WithClock(clock.NewFake(testEpoch)),
	}, opts...)
	s, err := New("huawei-intl", f.base(), base...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestFetchHealthySnapshotIsComplete(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.Complete {
		t.Errorf("snapshot is incomplete: %+v", snap.Warnings)
	}
	if len(snap.Open) != 0 {
		t.Errorf("got %d open, want 0", len(snap.Open))
	}
	if len(snap.Recent) != 1 {
		t.Errorf("got %d recent, want 1", len(snap.Recent))
	}
	if snap.UnresolvedCount != 0 {
		t.Errorf("unresolved count = %d, want 0", snap.UnresolvedCount)
	}
	if snap.SourceID != "huawei-intl" {
		t.Errorf("source id = %q", snap.SourceID)
	}
}

// Without the open list we know nothing about what is happening now, and
// returning a snapshot that says "nothing is open" would be the worst possible
// lie this service can tell.
func TestFetchCurrentEventsFailureIsFatal(t *testing.T) {
	r := healthyRoutes()
	r[pathCurrentEvents] = "error_500_endpoint_gone.json"
	f := newFakeSHD(t, r)
	s := newTestSource(t, f)

	snap, err := s.Fetch(t.Context())
	if err == nil {
		t.Fatal("expected an error when the open list is unavailable")
	}
	if snap != nil {
		t.Error("a failed fetch must not return a snapshot")
	}
	if !errors.Is(err, incident.ErrEndpointGone) {
		t.Errorf("got %v, want ErrEndpointGone", err)
	}
}

// Losing the resolved list must degrade, not fail: an open incident we can
// still see is worth reporting. But the snapshot cannot vouch for absence.
func TestFetchPastEventsFailureDegradesToIncomplete(t *testing.T) {
	r := healthyRoutes()
	r[pathPastEvents] = "html_body.html"
	f := newFakeSHD(t, r)
	s := newTestSource(t, f)

	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("a resolved-list failure must not fail the fetch, got %v", err)
	}
	if snap.Complete {
		t.Error("snapshot claims to be complete without the resolved list")
	}
	if len(snap.Warnings) == 0 {
		t.Error("the degradation was not reported as a warning")
	}
}

// The statistic endpoint is a free consistency oracle from a different code
// path: it is what catches an empty list caused by a silently ignored query
// parameter.
func TestFetchCountMismatchMarksIncomplete(t *testing.T) {
	f := newFakeSHD(t, routes{
		// The vendor reports zero unresolved while the list holds one.
		pathCurrentEvents: "current-events_one_open.json",
		pathPastEvents:    "past-events_event13.json",
		pathStatistic:     "event-statistic_ok.json",
	})
	s := newTestSource(t, f)

	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if snap.Complete {
		t.Error("a count disagreement must mark the snapshot incomplete")
	}
	if !hasAnomaly(snap.Warnings, incident.AnomalyCountMismatch) {
		t.Errorf("count mismatch not reported; warnings = %+v", snap.Warnings)
	}
	// The open incident must still be reported despite the disagreement.
	if len(snap.Open) != 1 {
		t.Errorf("got %d open, want 1", len(snap.Open))
	}
}

// A source that failed its own integrity check cannot vouch for absence,
// whatever the individual requests returned.
func TestFetchIsIncompleteAfterSelfCheckFailure(t *testing.T) {
	r := healthyRoutes()
	r[pathHistoryEvents] = "history-events_empty.json" // the known window went blank
	f := newFakeSHD(t, r)
	s := newTestSource(t, f)

	if err := s.SelfCheck(t.Context()); err == nil {
		t.Fatal("expected the self-check to fail on an empty known-good window")
	}
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if snap.Complete {
		t.Error("a snapshot from a source that failed its self-check must not be complete")
	}
}

// Omitting the explicit limit yields 1000 rows covering 9 of 17 regions, at
// HTTP 200 with no error and no pagination hint.
func TestServicesAlwaysSendsAnExplicitLimit(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	if _, err := s.Catalogue(t.Context(), 0); err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	var seen bool
	for _, u := range f.requested() {
		if !strings.Contains(u, pathServices) {
			continue
		}
		seen = true
		q, _ := url.Parse(u)
		if got := q.Query().Get("limit"); got != "10000" {
			t.Errorf("limit = %q, want %q", got, "10000")
		}
	}
	if !seen {
		t.Fatal("the catalogue endpoint was never requested")
	}
}

// The API accepts region_code, ignores it, and returns the full unfiltered list
// at HTTP 200. Sending it would make a filter that never filters.
func TestNeverSendsARegionCodeParameter(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f, WithRegions([]string{"ap-southeast-4"}, []string{"AP-Jakarta"}))

	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
	for _, u := range f.requested() {
		if strings.Contains(u, "region_code") || strings.Contains(u, "region_id") {
			t.Errorf("request carried a region parameter: %s", u)
		}
	}
}

// Every request must keep the base path prefix; losing it serves a different
// dataset at HTTP 200.
func TestEveryRequestKeepsTheDatasetPrefix(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
	got := f.requested()
	if len(got) == 0 {
		t.Fatal("no requests were made")
	}
	for _, u := range got {
		if !strings.HasPrefix(u, "/intl/") {
			t.Errorf("request lost the dataset prefix: %s", u)
		}
	}
}

func TestOnlyEverIssuesGET(t *testing.T) {
	var methods []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	s, err := New("huawei-intl", srv.URL+"/intl",
		WithHTTPClient(httpx.New(httpx.WithRetries(0))),
		WithClock(clock.NewFake(testEpoch)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("issued %s; this API answers HEAD and OPTIONS with 404 while GET returns 200", m)
		}
	}
}

func TestHistoryRequiresAStartTime(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	if _, err := s.client.historyEvents(t.Context(), time.Time{}, time.Time{}); !errors.Is(err, incident.ErrBadRequest) {
		t.Fatalf("got %v, want ErrBadRequest; omitting start_time returns an empty list, not an error", err)
	}
}

func TestHistorySendsSnakeCaseSecondsZulu(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	start := time.Date(2026, 7, 26, 2, 5, 0, 999000000, time.FixedZone("WIB", 7*3600))
	if _, err := s.client.historyEvents(t.Context(), start, time.Time{}); err != nil {
		t.Fatalf("historyEvents: %v", err)
	}
	for _, u := range f.requested() {
		if !strings.Contains(u, pathHistoryEvents) {
			continue
		}
		q, _ := url.Parse(u)
		got := q.Query().Get("start_time")
		if got != "2026-07-25T19:05:00Z" {
			t.Errorf("start_time = %q, want %q (no millis, no offset)", got, "2026-07-25T19:05:00Z")
		}
		if q.Query().Get("startTime") != "" {
			t.Error("camelCase parameter sent; the wire form is snake_case")
		}
	}
}

func TestSelfCheckPassesOnHealthyUpstream(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f, WithRegions([]string{"ap-southeast-4"}, []string{"AP-Jakarta"}))

	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
	if !s.SelfCheckOK() {
		t.Error("SelfCheckOK reported false after a passing check")
	}
}

// If a window that provably contained an incident now returns nothing, then an
// empty array means nothing anywhere.
func TestSelfCheckFailsWhenTheKnownWindowGoesBlank(t *testing.T) {
	r := healthyRoutes()
	r[pathHistoryEvents] = "history-events_empty.json"
	f := newFakeSHD(t, r)
	s := newTestSource(t, f)

	err := s.SelfCheck(t.Context())
	if err == nil {
		t.Fatal("expected a failure")
	}
	if !strings.Contains(err.Error(), "no longer be trusted") {
		t.Errorf("error should explain the consequence, got: %v", err)
	}
	if s.SelfCheckOK() {
		t.Error("SelfCheckOK reported true after a failing check")
	}
}

// The probe target is learned so that pruned history degrades the check rather
// than breaking it permanently.
func TestSelfCheckLearnsTheNewestEvent(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	s.mu.Lock()
	learned := s.learnedEvent
	s.mu.Unlock()

	if learned.ID != "13" {
		t.Errorf("learned event = %q, want %q", learned.ID, "13")
	}
	if learned.At.IsZero() {
		t.Error("learned window has no timestamp")
	}
}

func TestCatalogueResolvesJakartaToTheRightCode(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)

	c, err := s.Catalogue(t.Context(), 0)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	got, ok := c.CodeFor("AP-Jakarta")
	if !ok {
		t.Fatal("AP-Jakarta is not in the catalogue")
	}
	if got != "ap-southeast-4" {
		t.Errorf("AP-Jakarta resolved to %q, want %q", got, "ap-southeast-4")
	}
	// The neighbouring code belongs to a different region entirely.
	if name, _ := c.NameFor("ap-southeast-3"); name == "AP-Jakarta" {
		t.Error("ap-southeast-3 must not resolve to AP-Jakarta")
	}
}

func TestReconcileRegionsRejectsAMismatchedPair(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)
	c, err := s.Catalogue(t.Context(), 0)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}

	for _, tc := range []struct {
		name    string
		codes   []string
		names   []string
		wantErr bool
	}{
		{name: "correct pairing", codes: []string{"ap-southeast-4"}, names: []string{"AP-Jakarta"}},
		{
			// The failure this whole mechanism exists for.
			name:    "Jakarta paired with Singapore's code",
			codes:   []string{"ap-southeast-3"},
			names:   []string{"AP-Jakarta"},
			wantErr: true,
		},
		{name: "unknown code", codes: []string{"xx-nowhere-1"}, wantErr: true},
		{name: "unknown name", codes: []string{"ap-southeast-4"}, names: []string{"AP-Atlantis"}, wantErr: true},
		{name: "count mismatch", codes: []string{"ap-southeast-4"}, names: []string{"AP-Jakarta", "AP-Singapore"}, wantErr: true},
		{name: "codes only is fine", codes: []string{"ap-southeast-4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.ReconcileRegions(tc.codes, tc.names)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// The truncated page still CONTAINS the watched region, so a "can I find
// Jakarta?" check does not catch it. Only the totals do.
func TestCatalogueRejectsATruncatedPage(t *testing.T) {
	full := goldenDoc(t, "services_full.json")
	var rows []wireServiceRow
	if err := json.Unmarshal(full, &rows); err != nil {
		t.Fatalf("decoding catalogue: %v", err)
	}
	// The server's default page is byte-identical to the first 1000 rows, so
	// slicing reproduces it exactly without committing the fixture twice.
	truncated := buildCatalogue(rows[:1000])

	if _, ok := truncated.CodeFor("AP-Jakarta"); !ok {
		t.Fatal("fixture assumption broken: the watched region should still be present in the truncated page")
	}
	if err := truncated.Validate(false); !errors.Is(err, incident.ErrSchemaDrift) {
		t.Errorf("got %v, want ErrSchemaDrift for a truncated catalogue", err)
	}
	if err := buildCatalogue(rows).Validate(false); err != nil {
		t.Errorf("the full catalogue must validate, got %v", err)
	}
}

// A catalogue that is overwhelmingly mainland regions means the base URL lost
// its path prefix and we are reading the other site.
func TestCatalogueDetectsTheWrongDataset(t *testing.T) {
	rows := make([]wireServiceRow, 0, 1600)
	for i := 0; i < 100; i++ {
		for r := 0; r < 16; r++ {
			rows = append(rows, wireServiceRow{
				RegionCode: "cn-north-" + string(rune('a'+r)),
				RegionEN:   "CN-North",
				ServiceID:  "svc",
			})
		}
	}
	c := buildCatalogue(rows)
	if err := c.Validate(false); !errors.Is(err, incident.ErrWrongDataset) {
		t.Errorf("got %v, want ErrWrongDataset", err)
	}
	if err := c.Validate(true); err != nil {
		t.Errorf("an explicit override must permit it, got %v", err)
	}
}

func TestCatalogueIsCachedUntilStale(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	fake := clock.NewFake(testEpoch)
	s := newTestSource(t, f, WithClock(fake))

	if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if n := countRequests(f, pathServices); n != 1 {
		t.Errorf("made %d catalogue requests, want 1 (the second must be cached)", n)
	}

	fake.Advance(2 * time.Hour)
	if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if n := countRequests(f, pathServices); n != 2 {
		t.Errorf("made %d catalogue requests, want 2 after expiry", n)
	}
}

func countRequests(f *fakeSHD, path string) int {
	n := 0
	for _, u := range f.requested() {
		if strings.Contains(u, path) {
			n++
		}
	}
	return n
}

func TestCapabilitiesDescribeTheRealAPI(t *testing.T) {
	s, err := New("huawei-intl", DefaultBaseURL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := s.Capabilities()
	if c.HasExplicitStatus {
		t.Error("this API has no status field; claiming otherwise changes how the poller diffs")
	}
	if !c.ResolutionIsStructural {
		t.Error("resolution here is set membership and nothing else")
	}
	if c.HasUpdateTimestamp {
		t.Error("a record mtime exists only for resolved records, so this must be false")
	}
}

func TestDefaultBaseURLCarriesTheDatasetPrefix(t *testing.T) {
	if !strings.HasSuffix(DefaultBaseURL, "/intl") {
		t.Errorf("DefaultBaseURL = %q; without the prefix the same host serves the other dataset", DefaultBaseURL)
	}
	if !strings.HasSuffix(DefaultMirrorURL, "/intl") {
		t.Errorf("DefaultMirrorURL = %q; the mirror needs the prefix too", DefaultMirrorURL)
	}
}

func TestNewDefaultsAnEmptyBaseURL(t *testing.T) {
	s, err := New("x", "   ")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.client.base != DefaultBaseURL {
		t.Errorf("base = %q, want the default", s.client.base)
	}
}

var _ context.Context = context.Background()
