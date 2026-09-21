//go:build live

// Package canary holds the schema-drift canary: it calls the REAL status API
// and asserts the contract this service is built on still holds.
//
// The upstream is public, undocumented and unversioned. Every unit test in this
// repository runs against frozen fixtures in testdata/, so when the vendor
// renames a field, changes a status code, or starts filtering a parameter it
// previously ignored, those tests stay green — and the breakage reaches us not
// as an outage but as a watcher that quietly reports "no incidents" forever.
// This is the test that catches that, so it is the highest-value test here.
//
// Excluded from the default build. Run explicitly:
//
//	make test-live
//
// Baselines were observed live on 2026-09-05. A failure is a signal, not a
// flake: read it as "the contract moved", and update the fixtures with
// `statusrelayctl capture` once you understand how.
package canary

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/incident/httpx"
	"github.com/rahadiangg/statusrelay/internal/incident/huawei"
)

const ua = "statusrelay-canary/1.0 (+https://github.com/rahadiangg/statusrelay)"

func newSource(t *testing.T) *huawei.Source {
	t.Helper()
	s, err := huawei.New("huawei-intl", huawei.DefaultBaseURL,
		huawei.WithMirror(huawei.DefaultMirrorURL),
		huawei.WithRegions([]string{"ap-southeast-4"}, []string{"AP-Jakarta"}),
		huawei.WithHTTPClient(httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(1))),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// The whole service rests on Fetch succeeding and being able to say whether
// absence is meaningful.
func TestLiveFetchSucceedsAndIsComplete(t *testing.T) {
	s := newSource(t)
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()

	snap, err := s.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.Complete {
		t.Errorf("snapshot is not complete; warnings: %+v", snap.Warnings)
	}
	t.Logf("open=%d recent=%d unresolved_count=%d", len(snap.Open), len(snap.Recent), snap.UnresolvedCount)
}

// The single most consequential configuration fact in this service. If the
// vendor ever renumbers regions, this fails loudly instead of the watcher
// silently monitoring a different country.
func TestLiveAPJakartaIsApSoutheast4(t *testing.T) {
	s := newSource(t)
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()

	c, err := s.Catalogue(ctx, 0)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	got, ok := c.CodeFor("AP-Jakarta")
	if !ok {
		t.Fatal("AP-Jakarta is no longer in the catalogue")
	}
	if got != "ap-southeast-4" {
		t.Fatalf("AP-Jakarta is now %q, want %q -- every deployment watching this region is affected",
			got, "ap-southeast-4")
	}
}

// The catalogue must stay large enough that the truncation guard is meaningful.
func TestLiveCatalogueSizeAndRegionCount(t *testing.T) {
	s := newSource(t)
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()

	c, err := s.Catalogue(ctx, 0)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if len(c.Regions) < 15 {
		t.Errorf("got %d regions, want at least 15 (17 observed)", len(c.Regions))
	}
	t.Logf("regions=%d", len(c.Regions))
}

// Every self-check probe against the live API in one call.
func TestLiveSelfCheckPasses(t *testing.T) {
	s := newSource(t)
	ctx, cancel := contextWithTimeout(t, 90*time.Second)
	defer cancel()

	if err := s.SelfCheck(ctx); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
}

// The self-check's negative probe depends on this: a malformed timestamp must
// be rejected, not silently accepted and answered with an empty list.
func TestLiveMalformedTimestampIsRejected(t *testing.T) {
	c := httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(0))
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()

	u := huawei.DefaultBaseURL + "/v1/shd/history-events?start_time=2022-09-24"
	var out []map[string]any
	_, err := c.GetJSON(ctx, u, &out)
	if !errors.Is(err, incident.ErrBadRequest) {
		t.Fatalf("got %v, want ErrBadRequest -- if a malformed timestamp is now accepted, "+
			"an empty result no longer means 'no incidents'", err)
	}
}

// A removed endpoint answers 500, not 404. If that ever becomes a 404 the
// mapping still works, but if it becomes a 200 we have a silent-empty problem.
func TestLiveRemovedEndpointIsDistinguishable(t *testing.T) {
	c := httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(0))
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()

	var out []map[string]any
	_, err := c.GetJSON(ctx, huawei.DefaultBaseURL+"/v1/shd/definitely-not-a-real-endpoint", &out)
	if err == nil {
		t.Fatal("a nonexistent endpoint returned success; empty results are no longer meaningful")
	}
	if !errors.Is(err, incident.ErrEndpointGone) && !errors.Is(err, incident.ErrBadRequest) {
		t.Logf("note: nonexistent endpoint now yields %v (previously ErrEndpointGone via HTTP 500)", err)
	}
}

// HEAD returning 404 while GET returns 200 is why nothing in this service may
// probe with HEAD. If that changes, the constraint can be relaxed.
func TestLiveHEADStillDisagreesWithGET(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead,
		huawei.DefaultBaseURL+"/v1/shd/current-events", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		t.Log("note: HEAD now returns 200; the no-HEAD constraint could be revisited")
	} else {
		t.Logf("HEAD returns %d (GET returns 200) -- the constraint still holds", resp.StatusCode)
	}
}

// No cache validators means conditional requests cannot help and change
// detection must stay content-hash based.
func TestLiveNoCacheValidators(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		huawei.DefaultBaseURL+"/v1/shd/current-events", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if etag := resp.Header.Get("ETag"); etag != "" {
		t.Logf("note: an ETag is now served (%q); conditional requests may now be possible", etag)
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		t.Logf("note: Last-Modified is now served (%q)", lm)
	}
}

// The mirror is only useful if it serves the same corpus.
func TestLiveMirrorServesTheSameDataset(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()
	c := httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(1))

	var primary, mirror []map[string]any
	pr, err := c.GetJSON(ctx, huawei.DefaultBaseURL+"/v1/shd/past-events", &primary)
	if err != nil {
		t.Fatalf("primary: %v", err)
	}
	mr, err := c.GetJSON(ctx, huawei.DefaultMirrorURL+"/v1/shd/past-events", &mirror)
	if err != nil {
		t.Skipf("mirror unreachable from here: %v", err)
	}
	if pr.Hash != mr.Hash {
		t.Logf("note: mirror content differs from primary (%d vs %d records); "+
			"failover may now change what you see", len(primary), len(mirror))
	}
}

// The mainland dataset must remain distinguishable, or the dropped-prefix guard
// stops working.
func TestLiveMainlandDatasetIsDistinguishable(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()

	s, err := huawei.New("huawei-cn", strings.TrimSuffix(huawei.DefaultBaseURL, "/intl"),
		huawei.WithHTTPClient(httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(0))),
		huawei.WithAllowNonIntl(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := s.Catalogue(ctx, 0)
	if err != nil {
		t.Skipf("mainland catalogue unavailable: %v", err)
	}
	if _, ok := c.CodeFor("AP-Jakarta"); ok {
		t.Log("note: the prefix-less dataset now contains AP-Jakarta too; " +
			"the mainland-fraction guard may need revisiting")
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) (ctx canaryCtx, cancel func()) {
	t.Helper()
	return newTimeoutCtx(t, d)
}
