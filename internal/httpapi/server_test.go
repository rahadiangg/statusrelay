package httpapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rahadiangg/statwatch/internal/metrics"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
	"github.com/rahadiangg/statwatch/internal/poller"
)

var testEpoch = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

func newTestServer(t *testing.T, health func() poller.Health, clk clock.Clock) *httptest.Server {
	t.Helper()
	reg := prometheus.NewRegistry()
	metrics.New(reg, "v-test", "c0ffee").Init([]string{"huawei-intl"}, nil)
	s := New("127.0.0.1:0", reg, health, Thresholds{LoopStale: 3 * time.Minute, Clock: clk}, nil)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func healthy() poller.Health {
	return poller.Health{LastLoop: testEpoch, Sources: map[string]poller.SourceHealth{
		"huawei-intl": {EverComplete: true, LastComplete: testEpoch},
	}}
}

func TestMetricsEndpoint(t *testing.T) {
	srv := newTestServer(t, healthy, clock.NewFake(testEpoch))
	code, body := get(t, srv.URL+"/metrics")
	if code != 200 {
		t.Fatalf("got %d", code)
	}
	for _, want := range []string{
		`statwatch_build_info{commit="c0ffee",version="v-test"} 1`,
		`statwatch_source_blind{source="huawei-intl"} 0`,
		`go_goroutines`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body lacks %q", want)
		}
	}
}

func TestHealthz(t *testing.T) {
	for _, tc := range []struct {
		name string
		now  time.Time
		want int
	}{
		{name: "fresh", now: testEpoch.Add(time.Minute), want: 200},
		{name: "exactly at threshold", now: testEpoch.Add(3 * time.Minute), want: 200},
		{name: "just past threshold", now: testEpoch.Add(3*time.Minute + time.Second), want: 503},
		{name: "clock stepped backwards", now: testEpoch.Add(-time.Hour), want: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, healthy, clock.NewFake(tc.now))
			code, body := get(t, srv.URL+"/healthz")
			if code != tc.want {
				t.Errorf("got %d %q, want %d", code, body, tc.want)
			}
			if code == 503 && !strings.Contains(body, "loop stalled for") {
				t.Errorf("503 body should explain: %q", body)
			}
		})
	}
}

func TestReadyz(t *testing.T) {
	for _, tc := range []struct {
		name     string
		health   poller.Health
		want     int
		wantBody string
	}{
		{name: "ready", health: healthy(), want: 200, wantBody: `{"ready":true}`},
		{name: "never complete", health: poller.Health{Sources: map[string]poller.SourceHealth{"huawei-intl": {}}},
			want: 503, wantBody: `{"ready":false,"not_ready":{"huawei-intl":"no complete snapshot yet"}}`},
		{name: "blind", health: poller.Health{Sources: map[string]poller.SourceHealth{
			"huawei-intl": {EverComplete: true, Blind: true, LastComplete: testEpoch}}},
			want: 503, wantBody: `{"ready":false,"not_ready":{"huawei-intl":"blind since 2026-09-21T10:00:00Z"}}`},
		{name: "one of two blind", health: poller.Health{Sources: map[string]poller.SourceHealth{
			"b": {EverComplete: true, Blind: true, LastComplete: testEpoch},
			"a": {EverComplete: true}}},
			want: 503, wantBody: `{"ready":false,"not_ready":{"b":"blind since 2026-09-21T10:00:00Z"}}`},
		{name: "not started", health: poller.Health{}, want: 503, wantBody: `{"ready":false,"not_ready":{"*":"poller not started"}}`},
		{name: "started with empty map", health: poller.Health{Sources: map[string]poller.SourceHealth{}}, want: 200, wantBody: `{"ready":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.health
			srv := newTestServer(t, func() poller.Health { return h }, clock.NewFake(testEpoch))
			code, body := get(t, srv.URL+"/readyz")
			if code != tc.want || strings.TrimSpace(body) != tc.wantBody {
				t.Errorf("got %d %s, want %d %s", code, strings.TrimSpace(body), tc.want, tc.wantBody)
			}
		})
	}
}

func TestUnknownPathAndMethod(t *testing.T) {
	srv := newTestServer(t, healthy, clock.NewFake(testEpoch))
	if code, _ := get(t, srv.URL+"/nope"); code != 404 {
		t.Errorf("unknown path: got %d, want 404", code)
	}
	resp, err := http.Post(srv.URL+"/healthz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Errorf("POST /healthz: got %d, want 405", resp.StatusCode)
	}
}

func TestListenAndServeLifecycle(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := New("127.0.0.1:0", reg, healthy, Thresholds{LoopStale: time.Minute}, nil)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	// Listen bound synchronously, so the address is servable now.
	if code, body := get(t, "http://"+s.Addr()+"/healthz"); code != 200 {
		t.Errorf("healthz over real listener: %d %q", code, body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("got %v, want nil on clean shutdown", err)
	}
}

func TestServeWithoutListenBindsItself(t *testing.T) {
	s := New("127.0.0.1:0", prometheus.NewRegistry(), healthy, Thresholds{}, nil)
	if s.Addr() != "127.0.0.1:0" {
		t.Errorf("Addr before Listen: %q", s.Addr())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx); err != nil {
		t.Errorf("got %v", err)
	}
}

func TestListenAndServeBindFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	s := New(ln.Addr().String(), prometheus.NewRegistry(), healthy, Thresholds{}, nil)
	err = s.Listen()
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("got %v, want bind error", err)
	}
}

func TestLoopStaleFor(t *testing.T) {
	got := LoopStaleFor(time.Minute, 45*time.Second, 3)
	want := 2*time.Minute + 45*time.Second*5
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
