package httpx

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// newTestClient points a Client at h with retries and backoff disabled, so
// tests are fast and assert exactly one round trip unless they opt in.
func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	base := []Option{WithRetries(0), WithBackoff(0)}
	return New(append(base, opts...)...), srv
}

func TestGetJSONDecodesSuccess(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"event_id":13}]`))
	})

	var got []struct {
		EventID int `json:"event_id"`
	}
	res, err := c.GetJSON(t.Context(), srv.URL, &got)
	if err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if len(got) != 1 || got[0].EventID != 13 {
		t.Fatalf("got %+v, want one record with id 13", got)
	}
	if res.Hash == "" {
		t.Error("result carried no content hash")
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
}

func TestGetJSONDecodesGzip(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); !strings.Contains(got, "gzip") {
			t.Errorf("Accept-Encoding = %q, want it to offer gzip", got)
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`[]`))
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	})

	var got []any
	if _, err := c.GetJSON(t.Context(), srv.URL, &got); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d records, want 0", len(got))
	}
}

// The content hash is what lets a caller notice "nothing changed" without
// re-deriving it from parsed structures, so it must track the raw bytes.
func TestContentHashIsStableAndSensitive(t *testing.T) {
	hashOf := func(t *testing.T, body string) string {
		t.Helper()
		c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		res, err := c.GetJSON(t.Context(), srv.URL, nil)
		if err != nil {
			t.Fatalf("GetJSON: %v", err)
		}
		return res.Hash
	}

	a := hashOf(t, `{"a":1}`)
	if a != hashOf(t, `{"a":1}`) {
		t.Error("hash is not deterministic")
	}
	if a == hashOf(t, `{"a":2}`) {
		t.Error("different bodies hashed identically")
	}
}

func TestGetJSONErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		headers     map[string]string
		body        string
		wantErr     error
		wantNoRetry bool
	}{
		{
			// The signature of a challenge page served in place of the API.
			// Reading this as an empty result would be catastrophic.
			name:    "HTML body at 200 is not JSON",
			status:  200,
			body:    "<!DOCTYPE html><html><body>blocked</body></html>",
			wantErr: incident.ErrNotJSON,
		},
		{
			name:    "non-JSON content type at 200 is rejected",
			status:  200,
			headers: map[string]string{"Content-Type": "text/plain"},
			body:    "ok",
			wantErr: incident.ErrNotJSON,
		},
		{
			// Arrives as HTTP 500, not 404. Folding it into generic 5xx retry
			// noise would hide a permanent API removal for weeks.
			name:        "removed endpoint is distinct and not retried",
			status:      500,
			body:        `{"error_code":"SHD.10010004","error_msg":"APi not exists."}`,
			wantErr:     incident.ErrEndpointGone,
			wantNoRetry: true,
		},
		{
			name:        "bad parameter is a client error, never retried",
			status:      400,
			body:        `{"error_code":"SHD.0002","error_msg":"Invalid parameter values."}`,
			wantErr:     incident.ErrBadRequest,
			wantNoRetry: true,
		},
		{
			name:        "teapot is the WAF block signal and is never retried",
			status:      418,
			body:        "<html>blocked</html>",
			wantErr:     incident.ErrBlocked,
			wantNoRetry: true,
		},
		{
			name:        "a block id header means blocked even at 200",
			status:      200,
			headers:     map[string]string{"Block-Event-Id": "abc123"},
			body:        `[]`,
			wantErr:     incident.ErrBlocked,
			wantNoRetry: true,
		},
		{
			name:    "generic 5xx is transient",
			status:  503,
			body:    "unavailable",
			wantErr: incident.ErrUpstream,
		},
		{
			name:    "429 is transient",
			status:  429,
			body:    "slow down",
			wantErr: incident.ErrUpstream,
		},
		{
			name:        "404 is a client error",
			status:      404,
			body:        "nope",
			wantErr:     incident.ErrBadRequest,
			wantNoRetry: true,
		},
		{
			name:    "truncated JSON yields no partial result",
			status:  200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `[{"event_id":13`,
			wantErr: incident.ErrSchemaDrift,
		},
		{
			name:    "a top-level object where an array is expected is drift",
			status:  200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"unexpected":true}`,
			wantErr: incident.ErrSchemaDrift,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, WithRetries(2), WithBackoff(0))

			var got []any
			_, err := c.GetJSON(t.Context(), srv.URL, &got)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got error %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("a failed fetch produced a partial result: %+v", got)
			}
			if tc.wantNoRetry && calls != 1 {
				t.Errorf("made %d calls, want exactly 1 (this error must not be retried)", calls)
			}
		})
	}
}

func TestRetriesTransientThenSucceeds(t *testing.T) {
	calls := 0
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}, WithRetries(2), WithBackoff(0))

	var got []any
	if _, err := c.GetJSON(t.Context(), srv.URL, &got); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if calls != 3 {
		t.Errorf("made %d calls, want 3", calls)
	}
}

func TestRetryBudgetIsBounded(t *testing.T) {
	calls := 0
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}, WithRetries(2), WithBackoff(0))

	var got []any
	if _, err := c.GetJSON(t.Context(), srv.URL, &got); !errors.Is(err, incident.ErrUpstream) {
		t.Fatalf("got %v, want ErrUpstream", err)
	}
	if calls != 3 {
		t.Errorf("made %d calls, want 3 (initial + 2 retries)", calls)
	}
}

// A bad day upstream must be a failed poll, not an OOM kill of the watcher.
func TestBodyCapIsEnforced(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
	}, WithMaxBody(1024))

	if _, err := c.GetJSON(t.Context(), srv.URL, nil); !errors.Is(err, incident.ErrSchemaDrift) {
		t.Fatalf("got %v, want ErrSchemaDrift for an oversized body", err)
	}
}

// The cap must apply to the DECOMPRESSED stream, or a compression bomb slips
// through under a small compressed size.
func TestBodyCapAppliesAfterDecompression(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(bytes.Repeat([]byte("a"), 1<<20))
	_ = zw.Close()

	if buf.Len() > 64<<10 {
		t.Fatalf("fixture compressed to %d bytes; the test needs it small", buf.Len())
	}

	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}, WithMaxBody(64<<10))

	if _, err := c.GetJSON(t.Context(), srv.URL, nil); !errors.Is(err, incident.ErrSchemaDrift) {
		t.Fatalf("got %v, want ErrSchemaDrift; the cap must apply after decompression", err)
	}
}

func TestBodyExactlyAtCapIsAccepted(t *testing.T) {
	body := `["` + strings.Repeat("a", 60) + `"]`
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}, WithMaxBody(int64(len(body))))

	if _, err := c.GetJSON(t.Context(), srv.URL, nil); err != nil {
		t.Fatalf("a body exactly at the cap must be accepted, got %v", err)
	}
}

func TestSendsHonestUserAgent(t *testing.T) {
	var got string
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}, WithUserAgent("statwatch/1.0 (+mailto:ops@example.com)"))

	if _, err := c.GetJSON(t.Context(), srv.URL, nil); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if got != "statwatch/1.0 (+mailto:ops@example.com)" {
		t.Errorf("User-Agent = %q, want the configured value", got)
	}
}

// At least one upstream answers HEAD and OPTIONS with 404 while answering GET
// with 200, so any probe built on them reports a permanent false outage.
func TestOnlyEverIssuesGET(t *testing.T) {
	var methods []string
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})

	if _, err := c.GetJSON(t.Context(), srv.URL, nil); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("issued %s; only GET is permitted", m)
		}
	}
}

func TestContextCancellationIsSurfaced(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.GetJSON(ctx, srv.URL, nil); err == nil {
		t.Fatal("expected an error when the context expired")
	}
}

func TestRefuseUnsafeRedirect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		from    string
		to      string
		wantErr bool
	}{
		{name: "same host, prefix kept", from: "https://h/intl/v1/a", to: "https://h/intl/v1/b"},
		{
			// The path prefix selects the dataset; dropping it returns a
			// different corpus at HTTP 200.
			name:    "same host, prefix dropped",
			from:    "https://h/intl/v1/a",
			to:      "https://h/v1/a",
			wantErr: true,
		},
		{name: "different host", from: "https://h/intl/v1/a", to: "https://evil/intl/v1/a", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from, _ := url.Parse(tc.from)
			to, _ := url.Parse(tc.to)
			err := refuseUnsafeRedirect(&http.Request{URL: to}, []*http.Request{{URL: from}})
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("error = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, incident.ErrWrongDataset) {
				t.Errorf("got %v, want ErrWrongDataset", err)
			}
		})
	}
}

// Resolving "/v1/x" against a base carrying a path prefix is the standard way
// this goes wrong: url.Parse-and-replace silently selects another dataset.
func TestJoinPathNeverDropsTheBasePrefix(t *testing.T) {
	for _, tc := range []struct {
		name string
		base string
		rel  string
		q    url.Values
		want string
	}{
		{
			name: "absolute-looking rel keeps the prefix",
			base: "https://h/intl",
			rel:  "/v1/shd/current-events",
			want: "https://h/intl/v1/shd/current-events",
		},
		{
			name: "relative rel keeps the prefix",
			base: "https://h/intl",
			rel:  "v1/shd/current-events",
			want: "https://h/intl/v1/shd/current-events",
		},
		{
			name: "trailing slash on the base does not double up",
			base: "https://h/intl/",
			rel:  "/v1/shd/current-events",
			want: "https://h/intl/v1/shd/current-events",
		},
		{
			name: "query is encoded",
			base: "https://h/intl",
			rel:  "/v1/shd/services",
			q:    url.Values{"limit": {"10000"}, "offset": {"0"}},
			want: "https://h/intl/v1/shd/services?limit=10000&offset=0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JoinPath(tc.base, tc.rel, tc.q)
			if err != nil {
				t.Fatalf("JoinPath: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJoinPathRejectsBadBase(t *testing.T) {
	if _, err := JoinPath("://not a url", "/x", nil); !errors.Is(err, incident.ErrBadRequest) {
		t.Errorf("got %v, want ErrBadRequest", err)
	}
}
