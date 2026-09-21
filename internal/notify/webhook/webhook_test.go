package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/notify"
)

var update = flag.Bool("update", false, "rewrite golden files")

func goldenDoc(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture %s is empty; a golden test reading nothing passes vacuously", name)
	}
	return b
}

type capture struct {
	mu     sync.Mutex
	method string
	header http.Header
	body   []byte
}

func fakeReceiver(t *testing.T, status int, extra http.Header) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.method, c.header, c.body = r.Method, r.Header.Clone(), raw
		c.mu.Unlock()
		maps.Copy(w.Header(), extra)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"received":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func testEvent() incident.Event {
	r := incident.Record{
		Key:         incident.Key{SourceID: "huawei-intl", ProviderID: "13"},
		Title:       "Abnormal accounts in AP-Jakarta",
		TitleLang:   "en",
		Severity:    incident.SeverityMajor,
		RawSeverity: "2",
		Status:      incident.StatusOpen,
		StartedAt:   time.Date(2026, 7, 25, 19, 5, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 7, 27, 0, 4, 52, 0, time.UTC),
		Scope: []incident.Scope{
			{RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta", Services: []incident.Service{{Abbr: "ECS", Name: "Elastic Cloud Server"}}},
			{RegionCode: "tr-west-1", RegionName: "TR-Istanbul"},
		},
		Updates: []incident.Update{{At: time.Date(2026, 7, 25, 19, 5, 0, 0, time.UTC), Text: "Dear customer, …", Lang: "en"}},
	}
	r.FP = incident.Compute(r)
	return incident.Event{Kind: incident.KindNew, Record: r, NewUpdates: r.Updates}
}

func TestNewValidates(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		opts []Option
	}{
		{name: "empty", url: ""},
		{name: "relative", url: "/hooks/x"},
		{name: "ftp", url: "ftp://example.com/x"},
		{name: "no host", url: "https:///x"},
		{name: "header with CRLF", url: "https://example.com/x", opts: []Option{WithHeaders(map[string]string{"X-A": "v\r\nX-B: injected"})}},
		{name: "blank header name", url: "https://example.com/x", opts: []Option{WithHeaders(map[string]string{" ": "v"})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("x", tc.url, tc.opts...)
			if !errors.Is(err, notify.ErrPermanent) {
				t.Errorf("got err %v, want ErrPermanent", err)
			}
		})
	}
	if _, err := New("x", " https://example.com/hook "); err != nil {
		t.Errorf("surrounding whitespace should be tolerated: %v", err)
	}
}

func TestBuildGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   func() incident.Event
	}{
		{name: "event_new", ev: testEvent},
		{name: "event_scope_changed_zero_times", ev: func() incident.Event {
			ev := testEvent()
			ev.Kind = incident.KindScopeChanged
			ev.NewUpdates = nil
			ev.Added = []string{"ap-southeast-5/ECS"}
			ev.Record.Global = true
			ev.Record.Scope = nil
			ev.Record.StartedAt, ev.Record.UpdatedAt, ev.Record.EndedAt = time.Time{}, time.Time{}, time.Time{}
			ev.Record.Severity, ev.Record.RawSeverity = incident.SeverityUnknown, "7"
			ev.ColdStart = true
			return ev
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.MarshalIndent(Build(tc.ev()), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", tc.name+".json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if want := goldenDoc(t, tc.name+".json"); !bytes.Equal(got, want) {
				t.Errorf("payload mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestSendRequestShapeAndSignature(t *testing.T) {
	srv, c := fakeReceiver(t, 200, nil)
	n, err := New("n8n", srv.URL+"/hook", WithSecret("s3cret"), WithUserAgent("statusrelay/test"),
		WithHeaders(map[string]string{"Authorization": "Bearer abc"}), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Name(); got != "webhook/n8n" {
		t.Errorf("got name %q, want webhook/n8n", got)
	}
	ev := testEvent()
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send: %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.method != http.MethodPost {
		t.Errorf("got method %s, want POST", c.method)
	}
	for _, tc := range []struct{ name, want string }{
		{"Content-Type", "application/json"},
		{"User-Agent", "statusrelay/test"},
		{"Authorization", "Bearer abc"},
		{"X-Statusrelay-Event-Id", notify.EventID(ev)},
		{"X-Statusrelay-Event-Kind", "new"},
	} {
		if got := c.header.Get(tc.name); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// Verify the signature the way a receiver would: over the raw bytes.
	sig := strings.TrimPrefix(c.header.Get("X-Statusrelay-Signature"), "sha256=")
	if !hmac.Equal([]byte(sig), []byte(Sign([]byte("s3cret"), c.body))) {
		t.Errorf("signature does not verify: %q", sig)
	}
	var p Payload
	if err := json.Unmarshal(c.body, &p); err != nil {
		t.Fatalf("body is not the payload: %v", err)
	}
	if p.Schema != Schema || p.EventID != notify.EventID(ev) || p.Kind != "new" {
		t.Errorf("payload fields wrong: %+v", p)
	}
}

func TestSendWithoutSecretHasNoSignature(t *testing.T) {
	srv, c := fakeReceiver(t, 204, nil)
	n, _ := New("x", srv.URL)
	if err := n.Send(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.header["X-Statusrelay-Signature"]; ok {
		t.Error("signature header sent without a secret")
	}
}

func TestSendClassifiesResponses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		extra     http.Header
		want      error
		wantAfter time.Duration
	}{
		{name: "200", status: 200, want: nil},
		{name: "202", status: 202, want: nil},
		{name: "400", status: 400, want: notify.ErrPermanent},
		{name: "401", status: 401, want: notify.ErrPermanent},
		{name: "404", status: 404, want: notify.ErrPermanent},
		{name: "408", status: 408, want: notify.ErrTransient},
		{name: "425", status: 425, want: notify.ErrTransient},
		{name: "429 with Retry-After", status: 429, extra: http.Header{"Retry-After": {"30"}}, want: notify.ErrTransient, wantAfter: 30 * time.Second},
		{name: "429 without Retry-After", status: 429, want: notify.ErrTransient, wantAfter: 0},
		{name: "429 with HTTP-date Retry-After falls back", status: 429, extra: http.Header{"Retry-After": {"Wed, 21 Oct 2026 07:28:00 GMT"}}, want: notify.ErrTransient, wantAfter: 0},
		{name: "500", status: 500, want: notify.ErrTransient},
		{name: "503", status: 503, want: notify.ErrTransient},
		{name: "302 redirect refused", status: 302, extra: http.Header{"Location": {"https://evil.example/collect"}}, want: notify.ErrPermanent},
		{name: "307 redirect refused", status: 307, extra: http.Header{"Location": {"/elsewhere"}}, want: notify.ErrPermanent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, c := fakeReceiver(t, tc.status, tc.extra)
			n, _ := New("x", srv.URL, WithSecret("s"), WithHeaders(map[string]string{"Authorization": "Bearer t"}))
			err := n.Send(context.Background(), testEvent())
			if tc.want == nil {
				if err != nil {
					t.Fatalf("got err %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got err %v, want %v", err, tc.want)
			}
			if tc.status == http.StatusTooManyRequests {
				var rl *notify.RateLimited
				if !errors.As(err, &rl) {
					t.Fatalf("got %T, want *notify.RateLimited", err)
				}
				if rl.After != tc.wantAfter {
					t.Errorf("got After %s, want %s", rl.After, tc.wantAfter)
				}
			}
			if tc.status/100 == 3 {
				// Exactly one request must have reached the fake: the
				// redirect target was never contacted.
				c.mu.Lock()
				got := c.header.Get("Authorization")
				c.mu.Unlock()
				if got != "Bearer t" {
					t.Error("original request not observed")
				}
				if !strings.Contains(err.Error(), "redirect") {
					t.Errorf("error should explain the refusal: %v", err)
				}
			}
		})
	}
}

func TestSendTransportErrorsAreTransient(t *testing.T) {
	srv, _ := fakeReceiver(t, 200, nil)
	srv.Close()
	n, _ := New("x", srv.URL)
	err := n.Send(context.Background(), testEvent())
	if !errors.Is(err, notify.ErrTransient) {
		t.Errorf("got err %v, want ErrTransient", err)
	}
}

func TestSendRespectsContext(t *testing.T) {
	srv, _ := fakeReceiver(t, 200, nil)
	n, _ := New("x", srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.Send(ctx, testEvent()); !errors.Is(err, context.Canceled) {
		t.Errorf("got err %v, want context.Canceled", err)
	}
}
