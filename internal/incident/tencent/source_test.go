package tencent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

// routes maps an rpc path suffix to a fixture. A request to an unmapped path
// is a test failure, not a 404: production code reached for an endpoint the
// test did not expect. The history route may be a per-page map, keyed by
// PageNumber, for paging tests.
type routes struct {
	history  string
	pages    map[string]string
	progress string
	regions  string
}

type fakeAPI struct {
	srv  *httptest.Server
	mu   sync.Mutex
	urls []string
}

func newFakeAPI(t *testing.T, r routes) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		f.urls = append(f.urls, req.URL.String())
		f.mu.Unlock()

		var fixture string
		switch {
		case strings.HasSuffix(req.URL.Path, pathHistory):
			fixture = r.history
			if r.pages != nil {
				fixture = r.pages[req.URL.Query().Get("PageNumber")]
			}
		case strings.HasSuffix(req.URL.Path, pathProgress):
			fixture = r.progress
			// The real API answers an unknown code with an empty list at 200.
			if req.URL.Query().Get("HistoryEventCode") == "unknown" {
				fixture = "progress_empty.json"
			}
		case strings.HasSuffix(req.URL.Path, pathRegions):
			fixture = r.regions
		}
		if fixture == "" {
			t.Errorf("unexpected request to %s", req.URL.String())
			w.WriteHeader(http.StatusNotFound)
			return
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
		if strings.Contains(fixture, "error_500") {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write(body)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// base carries a path prefix so tests prove it survives every join.
func (f *fakeAPI) base() string { return f.srv.URL + "/prefix" }

func (f *fakeAPI) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.urls...)
}

func (f *fakeAPI) count(suffix string) int {
	n := 0
	for _, u := range f.requested() {
		p, _ := url.Parse(u)
		if strings.HasSuffix(p.Path, suffix) {
			n++
		}
	}
	return n
}

func healthyRoutes() routes {
	return routes{history: "history_12m.json", progress: "progress_seoul.json", regions: "regions_full.json"}
}

func newTestSource(t *testing.T, f *fakeAPI, opts ...Option) *Source {
	t.Helper()
	base := append([]Option{
		WithHTTPClient(httpx.New(httpx.WithRetries(0), httpx.WithBackoff(0))),
		WithClock(clock.NewFake(testEpoch)),
		WithRegions([]string{"ap-jakarta"}, []string{"Jakarta"}),
	}, opts...)
	s, err := New("tencent-intl", f.base(), base...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestFetchHealthySnapshotIsComplete(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f)

	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.Complete || len(snap.Open) != 0 || len(snap.Recent) != 5 || snap.UnresolvedCount != -1 {
		t.Errorf("got complete=%v open=%d recent=%d unresolved=%d", snap.Complete, len(snap.Open), len(snap.Recent), snap.UnresolvedCount)
	}
	if len(snap.Warnings) != 0 {
		t.Errorf("warnings on a healthy poll: %+v", snap.Warnings)
	}
	if !snap.FetchedAt.Equal(testEpoch) {
		t.Errorf("FetchedAt: got %v, want the injected clock", snap.FetchedAt)
	}
	// All five are months old, so no timeline is fetched for any of them.
	if n := f.count(pathProgress); n != 0 {
		t.Errorf("progress requests: got %d, want 0 for long-resolved records", n)
	}
}

// Every request must carry BelongSite and keep the base path prefix.
func TestEveryRequestKeepsPrefixAndSite(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f)
	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, u := range f.requested() {
		if !strings.HasPrefix(u, "/prefix/v1/api/") {
			t.Errorf("%s lost the base path prefix", u)
		}
		if !strings.Contains(u, "BelongSite=1") {
			t.Errorf("%s is missing BelongSite", u)
		}
	}
}

func TestFetchOpenEventGetsTimelineAndIsOpen(t *testing.T) {
	f := newFakeAPI(t, routes{history: "history_one_open.json", progress: "progress_seoul.json", regions: "regions_jakarta_flagged.json"})
	s := newTestSource(t, f)

	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Open) != 1 || len(snap.Recent) != 1 {
		t.Fatalf("got %d open, %d recent", len(snap.Open), len(snap.Recent))
	}
	r := snap.Open[0]
	if r.Status != incident.StatusOpen || r.Severity != incident.SeverityUnknown || !r.EndedAt.IsZero() {
		t.Errorf("open record wrong: %+v", r)
	}
	if len(r.Updates) != 5 || r.FP.Progress == "" {
		t.Errorf("timeline not attached: %d updates", len(r.Updates))
	}
	// Vendor flags ap-jakarta and we hold an open record there: consistent.
	if !snap.Complete || len(snap.Warnings) != 0 {
		t.Errorf("got complete=%v warnings=%+v", snap.Complete, snap.Warnings)
	}
	if n := f.count(pathProgress); n != 1 {
		t.Errorf("progress requests: got %d, want 1 (open only; the resolved one is old)", n)
	}
}

func TestFetchRecentlyResolvedGetsTimeline(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	// Four days after the Seoul event ended: inside the window.
	s := newTestSource(t, f, WithClock(clock.NewFake(time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC))))
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := findRec(t, snap.Recent, "93a75460e1115154b8cad11828c34ba7")
	if len(r.Updates) != 5 {
		t.Errorf("got %d updates, want 5", len(r.Updates))
	}
	if n := f.count(pathProgress); n != 1 {
		t.Errorf("progress requests: got %d, want 1", n)
	}
}

func TestFetchProgressFailureDegradesNotFails(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"empty timeline for a known code", "progress_empty.json"},
		{"endpoint renamed", "error_rpc_invalid.json"},
		{"upstream 500", "error_500.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, routes{history: "history_one_open.json", progress: tc.fixture, regions: "regions_jakarta_flagged.json"})
			s := newTestSource(t, f)
			snap, err := s.Fetch(t.Context())
			if err != nil {
				t.Fatalf("a timeline failure must not fail the poll: %v", err)
			}
			if len(snap.Open) != 1 || len(snap.Open[0].Updates) != 0 {
				t.Errorf("record lost or gained updates: %+v", snap.Open)
			}
			if !snap.Complete || !hasAnomaly(snap.Warnings, "progress_unavailable") {
				t.Errorf("got complete=%v warnings=%+v", snap.Complete, snap.Warnings)
			}
		})
	}
}

func TestFetchHistoryFailureIsFatal(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		want          error
	}{
		{"endpoint renamed", "error_rpc_invalid.json", incident.ErrEndpointGone},
		{"other vendor error", "error_other.json", incident.ErrUpstream},
		{"data null", "data_null.json", incident.ErrSchemaDrift},
		{"data wrong shape", "data_wrong_shape.json", incident.ErrSchemaDrift},
		{"html body", "html_body.html", incident.ErrNotJSON},
		{"http 500", "error_500.json", incident.ErrUpstream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, routes{history: tc.fixture, progress: "progress_seoul.json", regions: "regions_full.json"})
			s := newTestSource(t, f)
			snap, err := s.Fetch(t.Context())
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
			if snap != nil {
				t.Error("a failed list must not produce a snapshot")
			}
		})
	}
}

func TestFetchPaging(t *testing.T) {
	t.Run("walks every page", func(t *testing.T) {
		f := newFakeAPI(t, routes{pages: map[string]string{"1": "history_page1_of2.json", "2": "history_page2_of2.json"}, progress: "progress_seoul.json", regions: "regions_full.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Recent) != 3 || !snap.Complete {
			t.Errorf("got %d recent complete=%v", len(snap.Recent), snap.Complete)
		}
		if n := f.count(pathHistory); n != 2 {
			t.Errorf("history requests: got %d, want 2", n)
		}
	})
	t.Run("total shrinks mid-walk is incomplete", func(t *testing.T) {
		f := newFakeAPI(t, routes{pages: map[string]string{"1": "history_page1_of2.json", "2": "history_page2_shrunk.json"}, progress: "progress_seoul.json", regions: "regions_full.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if snap.Complete || !hasAnomaly(snap.Warnings, "history_truncated") || len(snap.Recent) != 2 {
			t.Errorf("got complete=%v recent=%d warnings=%+v", snap.Complete, len(snap.Recent), snap.Warnings)
		}
	})
	t.Run("empty page before total is incomplete, not a loop", func(t *testing.T) {
		f := newFakeAPI(t, routes{pages: map[string]string{"1": "history_page1_of2.json", "2": "history_page2_empty.json"}, progress: "progress_seoul.json", regions: "regions_full.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if snap.Complete || !hasAnomaly(snap.Warnings, "history_truncated") {
			t.Errorf("got complete=%v warnings=%+v", snap.Complete, snap.Warnings)
		}
		if n := f.count(pathHistory); n != 2 {
			t.Errorf("history requests: got %d, want 2 (stop on the empty page)", n)
		}
	})
	t.Run("page cap stops a runaway walk", func(t *testing.T) {
		// Every page claims Total=1000 and returns the same two rows: the
		// server ignores PageNumber. Dedup keeps 2 rows, the cap stops the
		// crawl, and the snapshot says so.
		pages := map[string]string{}
		for i := 1; i <= maxPages+5; i++ {
			pages[strconv.Itoa(i)] = "history_page_infinite.json"
		}
		f := newFakeAPI(t, routes{pages: pages, progress: "progress_seoul.json", regions: "regions_full.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if n := f.count(pathHistory); n != maxPages {
			t.Errorf("history requests: got %d, want %d", n, maxPages)
		}
		if len(snap.Recent) != 2 || snap.Complete || !hasAnomaly(snap.Warnings, "history_truncated") || !hasAnomaly(snap.Warnings, incident.AnomalyDuplicateID) {
			t.Errorf("got %d recent complete=%v warnings %+v", len(snap.Recent), snap.Complete, snap.Warnings)
		}
	})
}

func TestFetchUnkeyedRowMakesSnapshotIncomplete(t *testing.T) {
	f := newFakeAPI(t, routes{history: "history_zoo.json", progress: "progress_seoul.json", regions: "regions_full.json"})
	snap, err := newTestSource(t, f).Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete || !hasAnomaly(snap.Warnings, "unkeyed_event") {
		t.Errorf("got complete=%v warnings=%+v", snap.Complete, snap.Warnings)
	}
}

// The vendor's per-region flag is the only independent signal about what
// the list should contain.
func TestFetchRegionOracle(t *testing.T) {
	t.Run("flagged region with no open record is incomplete", func(t *testing.T) {
		f := newFakeAPI(t, routes{history: "history_12m.json", progress: "progress_seoul.json", regions: "regions_jakarta_flagged.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if snap.Complete || !hasAnomaly(snap.Warnings, incident.AnomalyCountMismatch) {
			t.Errorf("got complete=%v warnings=%+v", snap.Complete, snap.Warnings)
		}
	})
	t.Run("open record in an unflagged region is warned only", func(t *testing.T) {
		f := newFakeAPI(t, routes{history: "history_one_open.json", progress: "progress_seoul.json", regions: "regions_full.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !snap.Complete || !hasAnomaly(snap.Warnings, incident.AnomalyCountMismatch) {
			t.Errorf("got complete=%v warnings=%+v", snap.Complete, snap.Warnings)
		}
	})
	t.Run("flagged non-regional is covered by a Global record", func(t *testing.T) {
		f := newFakeAPI(t, routes{history: "history_zoo.json", progress: "progress_seoul.json", regions: "regions_global_flagged.json"})
		snap, err := newTestSource(t, f).Fetch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range snap.Warnings {
			if w.Kind == incident.AnomalyCountMismatch && strings.Contains(w.Detail, "vendor flags an event in non-regional") {
				t.Errorf("Global record should cover non-regional: %s", w.Detail)
			}
		}
	})
	t.Run("regions unavailable is incomplete", func(t *testing.T) {
		for _, fixture := range []string{"error_500.json", "error_rpc_invalid.json", "regions_truncated.json", "regions_no_jakarta.json"} {
			f := newFakeAPI(t, routes{history: "history_12m.json", progress: "progress_seoul.json", regions: fixture})
			snap, err := newTestSource(t, f).Fetch(t.Context())
			if err != nil {
				t.Fatalf("%s: %v", fixture, err)
			}
			if snap.Complete || !hasAnomaly(snap.Warnings, "regions_unavailable") {
				t.Errorf("%s: got complete=%v warnings=%+v", fixture, snap.Complete, snap.Warnings)
			}
		}
	})
}

func TestSelfCheck(t *testing.T) {
	t.Run("passes on a healthy upstream", func(t *testing.T) {
		f := newFakeAPI(t, healthyRoutes())
		s := newTestSource(t, f)
		if err := s.SelfCheck(t.Context()); err != nil {
			t.Fatalf("SelfCheck: %v", err)
		}
		if !s.SelfCheckOK() {
			t.Error("SelfCheckOK false after a pass")
		}
		if !strings.Contains(strings.Join(f.requested(), "\n"), "HistoryEventCode="+seedEventCode) {
			t.Error("did not probe the seed event before learning one")
		}
	})
	t.Run("probes the learned event after a fetch", func(t *testing.T) {
		f := newFakeAPI(t, routes{history: "history_one_open.json", progress: "progress_seoul.json", regions: "regions_jakarta_flagged.json"})
		s := newTestSource(t, f)
		if _, err := s.Fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := s.SelfCheck(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(f.requested(), "\n"), "HistoryEventCode=0000000000000000000000000000aa01") {
			t.Error("did not probe the newest learned event")
		}
	})
	t.Run("empty timeline for the known event fails and marks snapshots incomplete", func(t *testing.T) {
		f := newFakeAPI(t, routes{history: "history_12m.json", progress: "progress_empty.json", regions: "regions_full.json"})
		s := newTestSource(t, f)
		err := s.SelfCheck(t.Context())
		if !errors.Is(err, incident.ErrSchemaDrift) {
			t.Fatalf("got %v, want ErrSchemaDrift", err)
		}
		if s.SelfCheckOK() {
			t.Error("SelfCheckOK true after a failure")
		}
		snap, ferr := s.Fetch(t.Context())
		if ferr != nil {
			t.Fatal(ferr)
		}
		if snap.Complete {
			t.Error("snapshot complete after a failed self-check")
		}
	})
	t.Run("catalogue failures", func(t *testing.T) {
		for _, tc := range []struct {
			name, fixture string
			opts          []Option
			want          error
		}{
			{"too few regions", "regions_truncated.json", nil, incident.ErrSchemaDrift},
			{"missing sentinel region", "regions_no_jakarta.json", nil, incident.ErrWrongDataset},
			{"configured region unknown", "regions_full.json", []Option{WithRegions([]string{"ap-nowhere"}, nil)}, incident.ErrBadRequest},
			{"configured name mismatched", "regions_full.json", []Option{WithRegions([]string{"ap-jakarta"}, []string{"Singapore"})}, incident.ErrBadRequest},
			{"endpoint renamed", "error_rpc_invalid.json", nil, incident.ErrEndpointGone},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFakeAPI(t, routes{history: "history_12m.json", progress: "progress_seoul.json", regions: tc.fixture})
				s := newTestSource(t, f, tc.opts...)
				if err := s.SelfCheck(t.Context()); !errors.Is(err, tc.want) {
					t.Errorf("got %v, want %v", err, tc.want)
				}
			})
		}
	})
}

func TestCatalogueIsCachedUntilStale(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	clk := clock.NewFake(testEpoch)
	s := newTestSource(t, f, WithClock(clk))
	for i := 0; i < 3; i++ {
		if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count(pathRegions); n != 1 {
		t.Errorf("regions requests: got %d, want 1 (cached)", n)
	}
	clk.Advance(2 * time.Hour)
	if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := f.count(pathRegions); n != 2 {
		t.Errorf("regions requests after expiry: got %d, want 2", n)
	}
}

func TestCatalogueDuplicateRegionMergesFlag(t *testing.T) {
	var w wireRegions
	w.Areas = append(w.Areas, struct {
		Name    string       `json:"AreaName"`
		Regions []wireRegion `json:"RegionList"`
	}{Regions: []wireRegion{{ID: "ap-x", Name: "X"}, {ID: "ap-x", Name: "X", EventsIn: true}, {ID: " "}, {ID: "ap-y"}}})
	c := buildCatalogue(w)
	if len(c.Regions) != 2 || !c.EventsIn["ap-x"] {
		t.Errorf("got %+v flags=%v", c.Regions, c.EventsIn)
	}
	if name, _ := c.NameFor("ap-y"); name != "ap-y" {
		t.Errorf("blank name should fall back to the code, got %q", name)
	}
}

func TestReconcileRegionsNameCountMismatch(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f, WithRegions([]string{"ap-jakarta", "ap-singapore"}, []string{"Jakarta"}))
	if err := s.ValidateRegions(t.Context()); !errors.Is(err, incident.ErrBadRequest) {
		t.Errorf("got %v, want ErrBadRequest", err)
	}
}

func TestCapabilitiesAndDefaults(t *testing.T) {
	s, err := New("x", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.client.base != DefaultBaseURL || s.Kind() != "tencent" || s.ID() != "x" {
		t.Errorf("defaults wrong: base=%s kind=%s id=%s", s.client.base, s.Kind(), s.ID())
	}
	c := s.Capabilities()
	if !c.HasExplicitStatus || !c.HasUpdateTimestamp || c.ResolutionIsStructural || c.MaxHistoryLookback <= 0 {
		t.Errorf("capabilities wrong: %+v", c)
	}
}

func TestUserAgentReachesTheUpstream(t *testing.T) {
	var got string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("User-Agent")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Response":{"Data":{"Total":0,"List":[]}}}`))
	}))
	t.Cleanup(srv.Close)

	// No WithHTTPClient: this is the production construction path.
	s, err := New("tencent-intl", srv.URL,
		WithUserAgent("statwatch/v1.2.3"),
		WithClock(clock.NewFake(testEpoch)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _ = s.Fetch(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if got != "statwatch/v1.2.3" {
		t.Errorf("User-Agent: got %q, want %q", got, "statwatch/v1.2.3")
	}
}
