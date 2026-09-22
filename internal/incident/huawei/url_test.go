package huawei

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rahadiangg/statusrelay/internal/incident/httpx"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

func TestPageURL(t *testing.T) {
	for _, tc := range []struct{ name, base, id, want string }{
		{"default base", DefaultBaseURL, "13", "https://status.service.huaweicloud.com/intl/"},
		{"trailing slash not doubled", DefaultBaseURL + "/", "13", "https://status.service.huaweicloud.com/intl/"},
		{"mainland base links to mainland site", "https://status.service.huaweicloud.com", "7", "https://status.service.huaweicloud.com/"},
		{"id is ignored", DefaultBaseURL, "a b/c", "https://status.service.huaweicloud.com/intl/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pageURL(tc.base)(tc.id); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMappedRecordCarriesURL(t *testing.T) {
	f := newFakeSHD(t, healthyRoutes())
	s := newTestSource(t, f)
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(snap.Recent) == 0 {
		t.Fatal("fixture has no recent records")
	}
	r := snap.Recent[0]
	want := f.base() + "/"
	if r.URL != want {
		t.Errorf("URL: got %q, want %q", r.URL, want)
	}
	if snap.Mirror {
		t.Error("Mirror is true although the primary served the fetch")
	}
}

// A primary that fails on every request forces the mirror, and the snapshot
// must say so: a silently blocked primary is the precursor to going blind.
func TestSnapshotReportsMirrorAfterFailover(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(dead.Close)
	f := newFakeSHD(t, healthyRoutes())
	s, err := New("huawei-intl", dead.URL+"/intl",
		WithMirror(f.base()),
		WithHTTPClient(httpx.New(httpx.WithRetries(0), httpx.WithBackoff(0))),
		WithClock(clock.NewFake(testEpoch)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	snap, err := s.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch via mirror: %v", err)
	}
	if !snap.Mirror {
		t.Error("Mirror: got false, want true after the primary returned 502")
	}
}
