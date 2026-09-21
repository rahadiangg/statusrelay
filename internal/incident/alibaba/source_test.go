package alibaba

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/incident/httpx"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

var testEpoch = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// routes maps a request key to a fixture. Keys are an endpoint path, or
// "path?k=v" for a query-specific answer (detail by eventId, period by
// regionId), so one fake can answer every id the hydration step asks for.
type routes map[string]string

// recorded is one request as the fake saw it.
type recorded struct {
	method, url, lang, referer string
}

// fakeAPI serves fixtures and records every request, so tests can assert on
// the parameters and headers production code actually sent.
type fakeAPI struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []recorded
}

func newFakeAPI(t *testing.T, r routes) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{req.Method, req.URL.String(), req.Header.Get("Accept-Language"), req.Header.Get("Referer")})
		f.mu.Unlock()

		serve := func(fixture string) {
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
			_, _ = w.Write(body)
		}

		path := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		q := req.URL.Query()

		// The real API answers a period request without regionId with code
		// 400 in the envelope, and the catalogue without a Referer with 502.
		// The self-check depends on both, so the fake models them.
		if path == pathPeriod && q.Get("regionId") == "" {
			serve("envelope_400.json")
			return
		}
		if path == pathZones && req.Header.Get("Referer") == "" {
			serve("envelope_502_whitelist.json")
			return
		}

		for _, key := range []string{
			path + "?eventId=" + q.Get("eventId"),
			path + "?regionId=" + q.Get("regionId"),
			path + "?pageNumber=" + q.Get("pageNumber"),
			path,
		} {
			if fixture, ok := r[key]; ok {
				serve(fixture)
				return
			}
		}
		// A detail for an id no route names is what the real API does for an
		// unknown id: success with no rows.
		if path == pathDetail {
			serve("detail_unknown.json")
			return
		}
		if path == pathPeriod {
			serve("period_bogus_region.json")
			return
		}
		t.Errorf("unexpected request to %s", req.URL.String())
		w.WriteHeader(http.StatusNotFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// base carries a path prefix, mirroring production, so tests prove the prefix
// survives every join.
func (f *fakeAPI) base() string { return f.srv.URL + "/api/status" }

func (f *fakeAPI) requested() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recorded, len(f.reqs))
	copy(out, f.reqs)
	return out
}

func countRequests(f *fakeAPI, path string) int {
	n := 0
	for _, r := range f.requested() {
		if strings.Contains(r.url, path) {
			n++
		}
	}
	return n
}

// healthyRoutes is the everything-is-fine fixture set: nothing open, four
// resolved incidents, each with a detail record.
func healthyRoutes() routes {
	return routes{
		pathInProgress:                          "in-progress_empty.json",
		pathHistory:                             "history_page.json",
		pathZones:                               "zones_full.json",
		pathDetail + "?eventId=32":              "detail_32.json",
		pathDetail + "?eventId=33":              "detail_33.json",
		pathDetail + "?eventId=34":              "detail_34.json",
		pathDetail + "?eventId=35":              "detail_35.json",
		pathPeriod + "?regionId=ap-southeast-5": "period_ap-southeast-5.json",
	}
}

func testHTTP() doer {
	return httpx.New(httpx.WithRetries(0), httpx.WithBackoff(0),
		httpx.WithHeader("Accept-Language", "en"), httpx.WithHeader("Referer", Referer))
}

func newTestSource(t *testing.T, f *fakeAPI, opts ...Option) *Source {
	t.Helper()
	base := append([]Option{
		WithHTTPClient(testHTTP()),
		WithClock(clock.NewFake(testEpoch)),
		WithRegions([]string{"ap-southeast-5"}, []string{"Indonesia (Jakarta)"}),
	}, opts...)
	s, err := New("alibaba-intl", f.base(), base...)
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
	if !snap.Complete {
		t.Errorf("Complete = false, warnings %v", snap.Warnings)
	}
	if len(snap.Open) != 0 || len(snap.Recent) != 4 || snap.UnresolvedCount != 0 {
		t.Errorf("open=%d recent=%d unresolved=%d, want 0/4/0", len(snap.Open), len(snap.Recent), snap.UnresolvedCount)
	}
	if !snap.FetchedAt.Equal(testEpoch) {
		t.Errorf("FetchedAt = %v, want the injected clock", snap.FetchedAt)
	}
	if n := countRequests(f, pathDetail); n != 4 {
		t.Errorf("made %d detail requests, want 4 (one per history row)", n)
	}
	// Hydration worked: the abbreviated rows now carry scope and progress.
	for _, r := range snap.Recent {
		if len(r.Scope) == 0 || len(r.Updates) == 0 {
			t.Errorf("record %s not hydrated: scope=%d updates=%d", r.Key.ProviderID, len(r.Scope), len(r.Updates))
		}
	}
}

func TestFetchInProgressFailureIsFatal(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		want          error
	}{
		{"envelope code 500", "envelope_500.json", incident.ErrUpstream},
		{"envelope code 400", "envelope_400.json", incident.ErrBadRequest},
		{"html body", "html_body.html", incident.ErrNotJSON},
		{"object where array promised", "in-progress_object_not_array.json", incident.ErrSchemaDrift},
		{"bare object", "envelope_bare.json", incident.ErrSchemaDrift},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyRoutes()
			r[pathInProgress] = tc.fixture
			s := newTestSource(t, newFakeAPI(t, r))
			snap, err := s.Fetch(t.Context())
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if snap != nil {
				t.Error("a failed open-list fetch must not yield a snapshot")
			}
		})
	}
}

func TestEnvelopeClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  envelope
		want error
	}{
		{"success", envelope{Success: true, Code: 200}, nil},
		{"code 400", envelope{Code: 400, Info: "参数不合法"}, incident.ErrBadRequest},
		{"code 500", envelope{Code: 500}, incident.ErrUpstream},
		{"whitelist refusal", envelope{Code: 502, Info: "不在白名单"}, incident.ErrBadRequest},
		{"other 502", envelope{Code: 502, Info: "bad gateway"}, incident.ErrUpstream},
		{"no envelope", envelope{}, incident.ErrSchemaDrift},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyEnvelope(tc.env)
			if tc.want == nil && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDataNullDecodesToEmpty(t *testing.T) {
	r := healthyRoutes()
	r[pathInProgress] = "envelope_data_null.json"
	s := newTestSource(t, newFakeAPI(t, r))
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(snap.Open) != 0 || !snap.Complete {
		t.Errorf("open=%d complete=%v, want 0/true", len(snap.Open), snap.Complete)
	}
}

func TestFetchHistoryFailureDegradesToIncomplete(t *testing.T) {
	r := healthyRoutes()
	r[pathHistory] = "html_body.html"
	r[pathInProgress] = "in-progress_one_open.json"
	s := newTestSource(t, newFakeAPI(t, r))
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if snap.Complete {
		t.Error("Complete = true, want false without the resolved list")
	}
	if !hasAnomaly(snap.Warnings, "history_unavailable") {
		t.Errorf("want history_unavailable, got %v", snap.Warnings)
	}
	if len(snap.Open) != 1 || len(snap.Recent) != 0 {
		t.Errorf("open=%d recent=%d, want 1/0: the open incident must still be reported", len(snap.Open), len(snap.Recent))
	}
}

func TestFetchOpenRowIsHydratedFromDetail(t *testing.T) {
	r := healthyRoutes()
	r[pathInProgress] = "in-progress_one_open.json"
	r[pathDetail+"?eventId=35"] = "detail_35_open.json"
	s := newTestSource(t, newFakeAPI(t, r))
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(snap.Open) != 1 {
		t.Fatalf("got %d open, want 1", len(snap.Open))
	}
	o := snap.Open[0]
	if o.Status != incident.StatusOpen || len(o.Scope) != 1 || o.Scope[0].RegionCode != "ap-southeast-5" || len(o.Updates) != 5 {
		t.Errorf("open record = status %v scope %v updates %d", o.Status, o.Scope, len(o.Updates))
	}
	if !o.EndedAt.IsZero() {
		t.Errorf("EndedAt = %v, want zero for an open incident", o.EndedAt)
	}
}

func TestFetchOpenDetailFailureKeepsAbbreviatedRow(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"detail returns no record", "detail_unknown.json"},
		{"detail errors", "envelope_500.json"},
		{"detail returns two records", "detail_35_two_records.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyRoutes()
			r[pathInProgress] = "in-progress_one_open.json"
			r[pathDetail+"?eventId=35"] = tc.fixture
			s := newTestSource(t, newFakeAPI(t, r))
			snap, err := s.Fetch(t.Context())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if len(snap.Open) != 1 {
				t.Fatalf("got %d open, want 1: a missing detail must never drop an open incident", len(snap.Open))
			}
			o := snap.Open[0]
			if o.Title == "" || o.Severity != incident.SeverityMajor {
				t.Errorf("abbreviated row lost its list fields: %+v", o)
			}
			if o.Global {
				t.Error("Global = true; failing to look is not the vendor publishing no region")
			}
			if snap.Complete || !hasAnomaly(snap.Warnings, "detail_unavailable") {
				t.Errorf("complete=%v warnings=%v, want incomplete with detail_unavailable", snap.Complete, snap.Warnings)
			}
			// It still reaches a deployment that includes global events.
			f := incident.Filter{Regions: map[string]bool{"ap-southeast-5": true}, IncludeGlobal: true}
			if !f.Matches(o) {
				t.Error("a scopeless open record must still match via include_global")
			}
		})
	}
}

func TestFetchKnownIDVanishedFromDetail(t *testing.T) {
	r := healthyRoutes()
	delete(r, pathDetail+"?eventId=33") // the fake answers "no such event"
	s := newTestSource(t, newFakeAPI(t, r))
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(snap.Recent) != 4 {
		t.Errorf("got %d recent, want 4: the abbreviated row is kept", len(snap.Recent))
	}
	if snap.Complete || !hasAnomaly(snap.Warnings, "detail_unavailable") {
		t.Errorf("complete=%v warnings=%v", snap.Complete, snap.Warnings)
	}
}

func TestFetchCountMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, path, fixture string
		wantComplete        bool
	}{
		{"history total below page length", pathHistory, "history_total_lt_len.json", false},
		{"history total above page length is fine", pathHistory, "history_total_gt_len.json", true},
		{"open total disagrees with list", pathInProgress, "in-progress_total_mismatch.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyRoutes()
			r[tc.path] = tc.fixture
			s := newTestSource(t, newFakeAPI(t, r))
			snap, err := s.Fetch(t.Context())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if snap.Complete != tc.wantComplete {
				t.Errorf("Complete = %v, want %v (warnings %v)", snap.Complete, tc.wantComplete, snap.Warnings)
			}
			if hasAnomaly(snap.Warnings, incident.AnomalyCountMismatch) == tc.wantComplete {
				t.Errorf("count_mismatch present = %v, want %v", !tc.wantComplete, !tc.wantComplete)
			}
		})
	}
}

func TestFetchDuplicateAcrossListsWarnsButKeepsBoth(t *testing.T) {
	r := healthyRoutes()
	r[pathInProgress] = "in-progress_open_with_endtime.json" // 35, also in history
	s := newTestSource(t, newFakeAPI(t, r))
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(snap.Open) != 1 || len(snap.Recent) != 4 {
		t.Errorf("open=%d recent=%d, want 1/4", len(snap.Open), len(snap.Recent))
	}
	if !hasAnomaly(snap.Warnings, incident.AnomalyDuplicateID) {
		t.Errorf("want duplicate_id, got %v", snap.Warnings)
	}
	if !hasAnomaly(snap.Warnings, incident.AnomalyStatusConflict) {
		t.Errorf("want status_conflict for an open row with endTime, got %v", snap.Warnings)
	}
}

func TestDetailCacheHitSkipsRequest(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f)
	for i := 0; i < 2; i++ {
		if _, err := s.Fetch(t.Context()); err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
	}
	if n := countRequests(f, pathDetail); n != 4 {
		t.Errorf("made %d detail requests over two fetches, want 4 (second fetch served from cache)", n)
	}
}

func TestDetailCacheInvalidatesOnLastUpdateBump(t *testing.T) {
	r := healthyRoutes()
	f := newFakeAPI(t, r)
	s := newTestSource(t, f)
	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The vendor edits event 35: the history row's lastUpdateTime moves.
	r[pathHistory] = "history_bumped_35.json"
	r[pathDetail+"?eventId=35"] = "detail_35_bumped.json"
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if n := countRequests(f, pathDetail); n != 5 {
		t.Errorf("made %d detail requests, want 5 (only the bumped row re-fetched)", n)
	}
	if got := snap.Recent[3].UpdatedAt; !got.Equal(time.UnixMilli(1785230999000).UTC()) {
		t.Errorf("UpdatedAt = %v, want the bumped value", got)
	}
}

func TestOpenRowsAreNeverCached(t *testing.T) {
	r := healthyRoutes()
	r[pathInProgress] = "in-progress_one_open.json"
	r[pathDetail+"?eventId=35"] = "detail_35_open.json"
	f := newFakeAPI(t, r)
	s := newTestSource(t, f)
	for i := 0; i < 2; i++ {
		if _, err := s.Fetch(t.Context()); err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
	}
	// The open row is re-fetched on every poll; the history row for the same
	// id is fetched once and then served from the cache.
	if n := countRequests(f, pathDetail+"?eventId=35"); n != 3 {
		t.Errorf("made %d requests for the open event, want 3 (2 x open + 1 x history)", n)
	}
}

func TestHistoryAlwaysSendsPageParams(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f)
	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, r := range f.requested() {
		if strings.Contains(r.url, pathHistory) && !strings.Contains(r.url, "pageNumber=1&pageSize=200") {
			t.Errorf("history request %s lacks explicit paging", r.url)
		}
	}
}

func TestEveryRequestCarriesHeadersAndPrefix(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f)
	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
	reqs := f.requested()
	if len(reqs) < 8 {
		t.Fatalf("only %d requests recorded", len(reqs))
	}
	for _, r := range reqs {
		if r.method != http.MethodGet {
			t.Errorf("%s issued %s, want GET", r.url, r.method)
		}
		if r.lang != "en" || r.referer != Referer {
			t.Errorf("%s sent Accept-Language %q Referer %q", r.url, r.lang, r.referer)
		}
		if !strings.HasPrefix(r.url, "/api/status/") {
			t.Errorf("%s lost the base path prefix", r.url)
		}
		name := r.url[len("/api/status/"):]
		if i := strings.IndexByte(name, '?'); i >= 0 {
			name = name[:i]
		}
		if name != pathZones && !strings.HasSuffix(name, "International") {
			t.Errorf("%s is not the International endpoint", r.url)
		}
	}
}

func TestDefaultClientSendsHeaders(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s, err := New("alibaba-intl", f.base(), WithClock(clock.NewFake(testEpoch)), WithPreferLang("zh"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	r := f.requested()[0]
	if r.lang != "zh" || r.referer != Referer {
		t.Errorf("default client sent Accept-Language %q Referer %q", r.lang, r.referer)
	}
}

func TestCatalogueWithoutRefererIsRefused(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f, WithHTTPClient(httpx.New(httpx.WithRetries(0))))
	_, err := s.Catalogue(t.Context(), time.Hour)
	if !errors.Is(err, incident.ErrBadRequest) {
		t.Fatalf("got %v, want ErrBadRequest for a whitelist refusal", err)
	}
	if !strings.Contains(err.Error(), "Referer") {
		t.Errorf("error %q should name the missing header", err)
	}
}

func TestRedirectToOtherHostIsWrongDataset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://err.example.invalid/error1.html", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	s, err := New("alibaba-intl", srv.URL+"/api/status",
		WithHTTPClient(testHTTP()), WithClock(clock.NewFake(testEpoch)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Fetch(t.Context()); !errors.Is(err, incident.ErrWrongDataset) {
		t.Fatalf("got %v, want ErrWrongDataset: a renamed endpoint redirects off-host", err)
	}
}

func TestSelfCheckPassesOnHealthyUpstream(t *testing.T) {
	s := newTestSource(t, newFakeAPI(t, healthyRoutes()))
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
	if !s.SelfCheckOK() {
		t.Error("SelfCheckOK = false after a passing check")
	}
}

func TestSelfCheckFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(routes)
		want error
	}{
		{"known event vanishes", func(r routes) { r[pathDetail+"?eventId=35"] = "detail_unknown.json" }, incident.ErrSchemaDrift},
		{"detail answers a different id", func(r routes) { r[pathDetail+"?eventId=35"] = "detail_34.json" }, incident.ErrSchemaDrift},
		{"region no longer honoured", func(r routes) { r[pathPeriod+"?regionId=ap-southeast-5"] = "period_bogus_region.json" }, incident.ErrSchemaDrift},
		{"catalogue is the wrong dataset", func(r routes) { r[pathZones] = "zones_no_sentinel_zone.json" }, incident.ErrWrongDataset},
		{"catalogue is short", func(r routes) { r[pathZones] = "zones_few.json" }, incident.ErrWrongDataset},
		{"catalogue unreachable", func(r routes) { r[pathZones] = "html_body.html" }, incident.ErrNotJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyRoutes()
			tc.edit(r)
			s := newTestSource(t, newFakeAPI(t, r))
			err := s.SelfCheck(t.Context())
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if s.SelfCheckOK() {
				t.Error("SelfCheckOK = true after a failing check")
			}
		})
	}
}

func TestSelfCheckFailsWhenMissingRegionIsAccepted(t *testing.T) {
	// A fake whose period endpoint accepts anything: the bad-parameter probe
	// must notice that validation has vanished.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		fixture := map[string]string{
			pathDetail: "detail_35.json", pathPeriod: "period_ap-southeast-5.json", pathZones: "zones_full.json",
		}[path]
		body, _ := os.ReadFile(filepath.Join("testdata", fixture))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	s, err := New("alibaba-intl", srv.URL+"/api/status", WithHTTPClient(testHTTP()),
		WithClock(clock.NewFake(testEpoch)), WithRegions([]string{"ap-southeast-5"}, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.SelfCheck(t.Context())
	if !errors.Is(err, incident.ErrSchemaDrift) || !strings.Contains(err.Error(), "no regionId") {
		t.Fatalf("got %v, want ErrSchemaDrift about the accepted missing regionId", err)
	}
}

func TestSelfCheckLearnsTheNewestEvent(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	s := newTestSource(t, f)
	if _, err := s.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	s.mu.Lock()
	got := s.learned
	s.mu.Unlock()
	if got.ID != "35" || got.RegionID != "ap-southeast-5" || got.Start.IsZero() || got.End.IsZero() {
		t.Errorf("learned = %+v, want event 35 in ap-southeast-5", got)
	}
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
	// The probe window is derived from the learned event, not the seed.
	for _, r := range f.requested() {
		if strings.Contains(r.url, pathPeriod) && strings.Contains(r.url, "regionId=") {
			if !strings.Contains(r.url, "numOfDay=4") {
				t.Errorf("period probe %s, want a 4-day window around event 35", r.url)
			}
		}
	}
}

func TestSelfCheckUsesSeedForOpenLearnedEvent(t *testing.T) {
	s := newTestSource(t, newFakeAPI(t, healthyRoutes()))
	s.mu.Lock()
	s.learned = learnedEvent{ID: "35", RegionID: "ap-southeast-5", Start: seed.Start} // no End: still open
	s.mu.Unlock()
	if err := s.SelfCheck(t.Context()); err != nil {
		t.Fatalf("SelfCheck with an open learned event: %v", err)
	}
}

func TestFetchIsIncompleteAfterSelfCheckFailure(t *testing.T) {
	r := healthyRoutes()
	r[pathDetail+"?eventId=35"] = "detail_unknown.json"
	s := newTestSource(t, newFakeAPI(t, r))
	if err := s.SelfCheck(t.Context()); err == nil {
		t.Fatal("SelfCheck passed, want failure")
	}
	// Restore the upstream: the snapshot is still incomplete until the next
	// self-check clears it, because a source that failed its own integrity
	// check cannot vouch for absence.
	r[pathDetail+"?eventId=35"] = "detail_35.json"
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if snap.Complete {
		t.Error("Complete = true after a failed self-check")
	}
}

func TestCatalogueResolvesJakartaToTheRightCode(t *testing.T) {
	s := newTestSource(t, newFakeAPI(t, healthyRoutes()))
	c, err := s.Catalogue(t.Context(), time.Hour)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if code, _ := c.CodeFor("Indonesia (Jakarta)"); code != "ap-southeast-5" {
		t.Errorf("Jakarta = %q, want ap-southeast-5", code)
	}
	if name, _ := c.NameFor("ap-southeast-1"); name != "Singapore" {
		t.Errorf("ap-southeast-1 = %q, want Singapore", name)
	}
	if name, _ := c.NameFor("ap-southeast-3"); name != "Malaysia (Kuala Lumpur)" {
		t.Errorf("ap-southeast-3 = %q, want Malaysia (Kuala Lumpur)", name)
	}
	if len(c.Regions) != 37 {
		t.Errorf("got %d regions, want 37", len(c.Regions))
	}
}

func TestCatalogueValidation(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		want          error
	}{
		{"missing sentinel zone", "zones_no_sentinel_zone.json", incident.ErrWrongDataset},
		{"missing sentinel region", "zones_no_sentinel_region.json", incident.ErrWrongDataset},
		{"too few zones", "zones_few.json", incident.ErrWrongDataset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyRoutes()
			r[pathZones] = tc.fixture
			s := newTestSource(t, newFakeAPI(t, r))
			if _, err := s.Catalogue(t.Context(), time.Hour); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// Size floors are reached only once the sentinels pass.
	c := buildCatalogue([]wireZone{
		{Zone: struct {
			ZoneID   string `json:"zoneId"`
			ZoneName string `json:"zoneName"`
		}{ZoneID: nonRegional}, RegionList: []wireRegion{{RegionID: nonRegional}}},
		{RegionList: []wireRegion{{RegionID: "ap-southeast-1", RegionName: "Singapore"}}},
	})
	if err := c.Validate(); !errors.Is(err, incident.ErrSchemaDrift) {
		t.Errorf("got %v, want ErrSchemaDrift for a short catalogue with sentinels", err)
	}
}

func TestReconcileRegionsRejectsAMismatchedPair(t *testing.T) {
	s := newTestSource(t, newFakeAPI(t, healthyRoutes()))
	c, err := s.Catalogue(t.Context(), time.Hour)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	for _, tc := range []struct {
		name    string
		codes   []string
		names   []string
		wantErr bool
	}{
		{"correct pair", []string{"ap-southeast-5"}, []string{"Indonesia (Jakarta)"}, false},
		{"case-insensitive name", []string{"ap-southeast-5"}, []string{"indonesia (jakarta)"}, false},
		{"codes only", []string{"ap-southeast-5", "non-regional"}, nil, false},
		{"jakarta paired with singapore", []string{"ap-southeast-1"}, []string{"Indonesia (Jakarta)"}, true},
		{"jakarta paired with kuala lumpur", []string{"ap-southeast-3"}, []string{"Indonesia (Jakarta)"}, true},
		{"unknown code", []string{"ap-southeast-99"}, nil, true},
		{"unknown name", []string{"ap-southeast-5"}, []string{"Atlantis"}, true},
		{"length mismatch", []string{"ap-southeast-5", "ap-southeast-1"}, []string{"Indonesia (Jakarta)"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.ReconcileRegions(tc.codes, tc.names)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, incident.ErrBadRequest) {
				t.Errorf("got %v, want ErrBadRequest so the poller treats it as fatal", err)
			}
		})
	}
}

func TestValidateRegionsRejectsWrongCode(t *testing.T) {
	s := newTestSource(t, newFakeAPI(t, healthyRoutes()),
		WithRegions([]string{"ap-southeast-4"}, []string{"Indonesia (Jakarta)"}))
	if err := s.ValidateRegions(t.Context()); !errors.Is(err, incident.ErrBadRequest) {
		t.Fatalf("got %v, want ErrBadRequest: ap-southeast-4 is not Jakarta on this vendor", err)
	}
}

func TestCatalogueIsCachedUntilStale(t *testing.T) {
	f := newFakeAPI(t, healthyRoutes())
	fake := clock.NewFake(testEpoch)
	s := newTestSource(t, f, WithClock(fake))
	for i := 0; i < 2; i++ {
		if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
			t.Fatalf("Catalogue: %v", err)
		}
	}
	if n := countRequests(f, pathZones); n != 1 {
		t.Errorf("made %d catalogue requests, want 1", n)
	}
	fake.Advance(2 * time.Hour)
	if _, err := s.Catalogue(t.Context(), time.Hour); err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if n := countRequests(f, pathZones); n != 2 {
		t.Errorf("made %d catalogue requests, want 2 after expiry", n)
	}
}

func TestCapabilitiesAndIdentity(t *testing.T) {
	s, err := New("alibaba-intl", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.ID() != "alibaba-intl" || s.Kind() != "alibaba" {
		t.Errorf("id/kind = %s/%s", s.ID(), s.Kind())
	}
	if s.client.base != DefaultBaseURL {
		t.Errorf("empty base = %q, want the default", s.client.base)
	}
	c := s.Capabilities()
	if !c.HasExplicitStatus || !c.HasUpdateTimestamp || !c.ResolutionIsStructural || c.SupportsHistoryWindow || c.SupportsPostMortem {
		t.Errorf("capabilities = %+v", c)
	}
}

func TestPeriodRefusesEmptyRegionLocally(t *testing.T) {
	s := newTestSource(t, newFakeAPI(t, healthyRoutes()))
	if _, err := s.client.period(t.Context(), " ", testEpoch, 1); !errors.Is(err, incident.ErrBadRequest) {
		t.Fatalf("got %v, want ErrBadRequest", err)
	}
}
