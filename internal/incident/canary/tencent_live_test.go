//go:build live

package canary

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
	"github.com/rahadiangg/statwatch/internal/incident/tencent"
)

// Baselines observed live on 2026-09-21. The corpus is tiny (8 events since
// 2024-04), so most assertions are about shape and traps, not volume.

const tencentSeed = "93a75460e1115154b8cad11828c34ba7" // 2026-04-21 Seoul cooling incident

func newTencentSource(t *testing.T) *tencent.Source {
	t.Helper()
	s, err := tencent.New("tencent-intl", tencent.DefaultBaseURL,
		tencent.WithRegions([]string{"ap-jakarta"}, []string{"Jakarta"}),
		tencent.WithHTTPClient(httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(1))),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// rawTencent calls one rpc directly and returns the decoded envelope, for the
// probes that need to see the wire rather than the adapter's reading of it.
func rawTencent(t *testing.T, ctx canaryCtx, rpc string, q url.Values) (data json.RawMessage, apiErr map[string]any, err error) {
	t.Helper()
	if q == nil {
		q = url.Values{}
	}
	q.Set("BelongSite", "1")
	u, err := httpx.JoinPath(tencent.DefaultBaseURL, rpc, q)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Response struct {
			Error map[string]any  `json:"Error"`
			Data  json.RawMessage `json:"Data"`
		} `json:"Response"`
	}
	_, err = httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(1)).GetJSON(ctx, u, &env)
	return env.Response.Data, env.Response.Error, err
}

func TestLiveTencentFetchSucceedsAndIsComplete(t *testing.T) {
	s := newTencentSource(t)
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()

	snap, err := s.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.Complete {
		t.Errorf("snapshot incomplete: %+v", snap.Warnings)
	}
	for _, w := range snap.Warnings {
		t.Errorf("anomaly on a live poll: %s: %s", w.Kind, w.Detail)
	}
	// Every status value must be one we mapped; a new one alerts as Open
	// with an unknown_status anomaly, which the loop above already catches.
	// Every row must have parsed its start time.
	for _, r := range append(snap.Open, snap.Recent...) {
		if r.StartedAt.IsZero() {
			t.Errorf("%s: StartedAt did not parse", r.Key.ProviderID)
		}
		if r.Status == incident.StatusResolved && r.EndedAt.IsZero() {
			t.Errorf("%s: resolved without EndedAt", r.Key.ProviderID)
		}
	}
}

func TestLiveTencentSelfCheckPasses(t *testing.T) {
	s := newTencentSource(t)
	ctx, cancel := contextWithTimeout(t, 60*time.Second)
	defer cancel()
	if err := s.SelfCheck(ctx); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
}

func TestLiveTencentCatalogueShape(t *testing.T) {
	s := newTencentSource(t)
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	c, err := s.Catalogue(ctx, 0)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if len(c.Regions) < 15 {
		t.Errorf("got %d regions, want >= 15", len(c.Regions))
	}
	for _, want := range []string{"ap-jakarta", "ap-singapore", "non-regional"} {
		if _, ok := c.NameFor(want); !ok {
			t.Errorf("region %s missing from the catalogue", want)
		}
	}
	if code, _ := c.CodeFor("Jakarta"); code != "ap-jakarta" {
		t.Errorf("Jakarta resolves to %q, want ap-jakarta", code)
	}
}

// The seed event must still be in the 36-month window with a non-empty
// timeline; this is the known-good probe the self-check falls back to.
func TestLiveTencentSeedEventStillExists(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()

	data, apiErr, err := rawTencent(t, ctx, "v1/api/ops/DescribeHistoryEventList",
		url.Values{"PageSize": {"100"}, "PageNumber": {"1"}, "GapMonth": {"36"}})
	if err != nil || apiErr != nil {
		t.Fatalf("history: err=%v apiErr=%v", err, apiErr)
	}
	var h struct {
		Total int
		List  []struct {
			EventCode string
			Status    json.Number
			StartTime string
		}
	}
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatal(err)
	}
	if h.Total < 8 || len(h.List) != h.Total {
		t.Errorf("Total=%d len=%d; want >= 8 and equal (page walk depends on it)", h.Total, len(h.List))
	}
	found := false
	for _, e := range h.List {
		if e.EventCode == tencentSeed {
			found = true
		}
		switch e.Status.String() {
		case "0", "1", "2":
		default:
			t.Errorf("%s: unmapped status %q", e.EventCode, e.Status)
		}
		if _, err := time.Parse("2006-01-02 15:04:05", e.StartTime); err != nil {
			t.Errorf("%s: StartTime %q no longer matches the layout", e.EventCode, e.StartTime)
		}
	}
	if !found {
		t.Errorf("seed event %s absent from a 36-month window; update the seed", tencentSeed)
	}

	data, apiErr, err = rawTencent(t, ctx, "v1/api/ops/DescribeHistoryEventProgress", url.Values{"HistoryEventCode": {tencentSeed}})
	if err != nil || apiErr != nil {
		t.Fatalf("progress: err=%v apiErr=%v", err, apiErr)
	}
	var p struct{ ProgressList []json.RawMessage }
	if err := json.Unmarshal(data, &p); err != nil || len(p.ProgressList) == 0 {
		t.Errorf("seed timeline: err=%v len=%d, want non-empty", err, len(p.ProgressList))
	}
}

// Trap 2: an unknown event code answers 200 with an empty list. The
// self-check's meaning depends on this; if it starts erroring instead, the
// probe must change.
func TestLiveTencentUnknownCodeIsEmptyNotError(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	data, apiErr, err := rawTencent(t, ctx, "v1/api/ops/DescribeHistoryEventProgress", url.Values{"HistoryEventCode": {"statwatch-canary-nope"}})
	if err != nil || apiErr != nil {
		t.Fatalf("err=%v apiErr=%v; the trap has changed shape", err, apiErr)
	}
	if !strings.Contains(string(data), `"ProgressList":[]`) && !strings.Contains(string(data), `"ProgressList": []`) {
		t.Errorf("unknown code returned %s, want an empty ProgressList", data)
	}
}

// Trap 4: a renamed endpoint is HTTP 200 with an Error object. The adapter
// maps that to ErrEndpointGone; this proves the message shape it keys on.
func TestLiveTencentRenamedEndpointIsDetectable(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	_, apiErr, err := rawTencent(t, ctx, "v1/api/ops/DescribeNothingCanary", nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	msg, _ := apiErr["Message"].(string)
	if apiErr["Code"] != "InternalError" || !strings.Contains(msg, "rpc name") {
		t.Errorf("got %v; the adapter keys ErrEndpointGone on Code=InternalError and 'rpc name'", apiErr)
	}
}

// Trap 3: BelongSite is ignored. If it ever starts selecting a dataset, the
// hardcoded value in the adapter becomes load-bearing and needs a config knob.
func TestLiveTencentBelongSiteIsIgnored(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	total := func(site string) int {
		q := url.Values{"PageSize": {"100"}, "PageNumber": {"1"}, "GapMonth": {"36"}}
		u, _ := httpx.JoinPath(tencent.DefaultBaseURL, "v1/api/ops/DescribeHistoryEventList", q)
		u += "&BelongSite=" + site
		var env struct {
			Response struct {
				Data struct{ Total int } `json:"Data"`
			} `json:"Response"`
		}
		if _, err := httpx.New(httpx.WithUserAgent(ua)).GetJSON(ctx, u, &env); err != nil {
			t.Fatal(err)
		}
		return env.Response.Data.Total
	}
	if a, b := total("1"), total("0"); a != b {
		t.Errorf("BelongSite=1 gives %d events, BelongSite=0 gives %d; the parameter now selects a dataset", a, b)
	}
}

// Sanity: the adapter's error mapping holds against the real thing.
func TestLiveTencentAdapterMapsRenamedEndpoint(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	s, err := tencent.New("x", tencent.DefaultBaseURL+"/does-not-exist",
		tencent.WithHTTPClient(httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(0))))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Fetch(ctx)
	if err == nil {
		t.Fatal("a wrong base path fetched successfully")
	}
	if !errors.Is(err, incident.ErrEndpointGone) && !errors.Is(err, incident.ErrNotJSON) && !errors.Is(err, incident.ErrBadRequest) {
		t.Errorf("got %v, want a classified sentinel", err)
	}
}
