//go:build live

package canary

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/incident/alibaba"
	"github.com/rahadiangg/statusrelay/internal/incident/httpx"
)

// Baselines were observed live on 2026-09-21: four resolved incidents (ids
// 32-35), none open, 7 zones and 37 regions in the catalogue.

func newAlibabaSource(t *testing.T) *alibaba.Source {
	t.Helper()
	s, err := alibaba.New("alibaba-intl", alibaba.DefaultBaseURL,
		alibaba.WithRegions([]string{"ap-southeast-5"}, []string{"Indonesia (Jakarta)"}),
		alibaba.WithUserAgent(ua),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func alibabaHTTP() *httpx.Client {
	return httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(0),
		httpx.WithHeader("Accept-Language", "en"), httpx.WithHeader("Referer", alibaba.Referer))
}

// alibabaEnvelope mirrors the wire envelope for raw probes.
type alibabaEnvelope struct {
	Data    json.RawMessage `json:"data"`
	Total   int             `json:"total"`
	Info    string          `json:"info"`
	Code    int             `json:"code"`
	Success bool            `json:"success"`
}

func TestLiveAlibabaFetchSucceedsAndIsComplete(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 90*time.Second)
	defer cancel()
	snap, err := newAlibabaSource(t).Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.Complete {
		t.Errorf("snapshot incomplete: %v", snap.Warnings)
	}
	if len(snap.Recent) < 4 {
		t.Errorf("got %d resolved incidents, want at least the 4 on record", len(snap.Recent))
	}
	for _, r := range snap.Recent {
		if len(r.Scope) == 0 && !r.Global {
			t.Errorf("event %s has no scope and is not global; detail hydration may have stopped working", r.Key.ProviderID)
		}
	}
}

// Jakarta is ap-southeast-5 on this vendor. The English name only comes back
// with Accept-Language, so this also proves the header is still honoured.
func TestLiveAlibabaJakartaIsApSoutheast5(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	c, err := newAlibabaSource(t).Catalogue(ctx, 0)
	if err != nil {
		t.Fatalf("Catalogue: %v", err)
	}
	if code, ok := c.CodeFor("Indonesia (Jakarta)"); !ok || code != "ap-southeast-5" {
		t.Fatalf("Indonesia (Jakarta) = %q (found=%v), want ap-southeast-5", code, ok)
	}
	if name, _ := c.NameFor("ap-southeast-1"); name != "Singapore" {
		t.Errorf("ap-southeast-1 = %q, want Singapore", name)
	}
	if len(c.Regions) < 25 {
		t.Errorf("got %d regions, want at least 25", len(c.Regions))
	}
}

func TestLiveAlibabaSelfCheckPasses(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 90*time.Second)
	defer cancel()
	if err := newAlibabaSource(t).SelfCheck(ctx); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}
}

// The detail record is the only place scope and progress live. Every field
// the mapper reads must still be there.
func TestLiveAlibabaDetail35Shape(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	var env alibabaEnvelope
	if _, err := alibabaHTTP().GetJSON(ctx, alibaba.DefaultBaseURL+"/getEventDetailInternational?eventId=35", &env); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(env.Data, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("data = %s (err %v), want one row", env.Data, err)
	}
	for _, k := range []string{"id", "title", "eventType", "startTime", "endTime", "lastUpdateTime", "products", "regions", "eventUpdates"} {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("detail row lacks %q", k)
		}
	}
	if rows[0]["eventType"] != "ALARM" {
		t.Errorf("eventType = %v, want ALARM", rows[0]["eventType"])
	}
}

// Errors are HTTP 200 with success:false. If a missing regionId ever becomes
// a success, the region filter probe loses its meaning.
func TestLiveAlibabaMissingRegionIs400Envelope(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	var env alibabaEnvelope
	if _, err := alibabaHTTP().GetJSON(ctx, alibaba.DefaultBaseURL+"/listProductStatusInPeriodInternational?endTime=1785400000000&numOfDay=1", &env); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if env.Success || env.Code != 400 {
		t.Fatalf("envelope = success %v code %d, want success:false code:400", env.Success, env.Code)
	}
}

// The catalogue needs a Referer. If it stops needing one, nothing breaks; if
// the incident endpoints START needing one, this is the early warning.
func TestLiveAlibabaRefererGate(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	bare := httpx.New(httpx.WithUserAgent(ua), httpx.WithRetries(0))
	var env alibabaEnvelope
	if _, err := bare.GetJSON(ctx, alibaba.DefaultBaseURL+"/listProductRegionInAllZone", &env); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if env.Success {
		t.Log("note: the catalogue no longer requires a Referer header")
	}
	if _, err := bare.GetJSON(ctx, alibaba.DefaultBaseURL+"/listEventInProgressInternational", &env); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if !env.Success {
		t.Errorf("the open-incident list now refuses requests without a Referer: code %d %q", env.Code, env.Info)
	}
}

// The open list has never been observed non-empty. Assert it at least still
// decodes as the same envelope so the day it fills we are not guessing.
func TestLiveAlibabaInProgressDecodes(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	var env alibabaEnvelope
	if _, err := alibabaHTTP().GetJSON(ctx, alibaba.DefaultBaseURL+"/listEventInProgressInternational", &env); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if !env.Success {
		t.Fatalf("envelope = code %d %q, want success", env.Code, env.Info)
	}
	var rows []map[string]any
	if err := json.Unmarshal(env.Data, &rows); err != nil {
		t.Fatalf("data is not an array of rows: %s", env.Data)
	}
	if len(rows) > 0 {
		t.Logf("note: %d incident(s) currently open; first row keys: %v", len(rows), rows[0])
	}
}

// A renamed endpoint redirects to an error page on another host, which the
// shared client refuses. If it ever becomes a 200 we have a silent-empty
// problem.
func TestLiveAlibabaRenamedEndpointIsWrongDataset(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	var env alibabaEnvelope
	_, err := alibabaHTTP().GetJSON(ctx, alibaba.DefaultBaseURL+"/definitelyNotARealEndpointInternational", &env)
	if err == nil {
		t.Fatal("a nonexistent endpoint returned success; empty results are no longer meaningful")
	}
	if !errors.Is(err, incident.ErrWrongDataset) {
		t.Logf("note: nonexistent endpoint now yields %v (previously a 302 to err.taobao.com)", err)
	}
}

// The unsuffixed names serve the same corpus today. Log-only: divergence is
// worth knowing about, not worth failing the build over.
func TestLiveAlibabaNonInternationalServesSameCorpus(t *testing.T) {
	ctx, cancel := contextWithTimeout(t, 30*time.Second)
	defer cancel()
	c := alibabaHTTP()
	intl, err := c.GetJSON(ctx, alibaba.DefaultBaseURL+"/listHistoryEventInternational?pageNumber=1&pageSize=50", nil)
	if err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	cn, err := c.GetJSON(ctx, alibaba.DefaultBaseURL+"/listHistoryEvent?pageNumber=1&pageSize=50", nil)
	if err != nil {
		t.Skipf("unsuffixed endpoint unreachable: %v", err)
	}
	if intl.Hash != cn.Hash {
		t.Logf("note: listHistoryEvent and listHistoryEventInternational now differ; the suffix has become load-bearing")
	}
}
