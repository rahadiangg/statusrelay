package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/notify"
)

const testToken = "123456:ABC-secret-token"

type capture struct {
	mu   sync.Mutex
	path string
	ua   string
	body sendMessage
}

// fakeAPI answers every request with the given status and body, recording
// the last request.
func fakeAPI(t *testing.T, status int, reply string) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.path = r.URL.Path
		c.ua = r.Header.Get("User-Agent")
		_ = json.Unmarshal(raw, &c.body)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func testEvent() incident.Event {
	r := incident.Record{
		Key:      incident.Key{SourceID: "huawei-intl", ProviderID: "13"},
		Title:    "Abnormal accounts in AP-Jakarta",
		Severity: incident.SeverityMajor,
		Status:   incident.StatusOpen,
		Scope:    []incident.Scope{{RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta"}},
	}
	r.FP = incident.Compute(r)
	return incident.Event{Kind: incident.KindNew, Record: r}
}

func TestNewRejectsEmptyConfig(t *testing.T) {
	for _, tc := range []struct{ name, token, chat string }{
		{name: "empty token", token: "", chat: "1"},
		{name: "blank token", token: "  ", chat: "1"},
		{name: "empty chat", token: testToken, chat: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("x", tc.token, tc.chat)
			if !errors.Is(err, notify.ErrPermanent) {
				t.Errorf("got err %v, want ErrPermanent", err)
			}
		})
	}
}

func TestSendRequestShape(t *testing.T) {
	srv, c := fakeAPI(t, 200, `{"ok":true,"result":{}}`)
	n, err := New("oncall", testToken, "-100123", WithBaseURL(srv.URL+"/"), WithThreadID(42), WithUserAgent("statwatch/test"))
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Name(); got != "telegram/oncall" {
		t.Errorf("got name %q, want telegram/oncall", got)
	}
	if err := n.Send(context.Background(), testEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if want := "/bot" + testToken + "/sendMessage"; c.path != want {
		t.Errorf("got path %q, want %q", c.path, want)
	}
	if c.ua != "statwatch/test" {
		t.Errorf("got UA %q, want statwatch/test", c.ua)
	}
	if c.body.ChatID != "-100123" {
		t.Errorf("got chat_id %q, want -100123", c.body.ChatID)
	}
	if c.body.MessageThreadID != 42 {
		t.Errorf("got message_thread_id %d, want 42", c.body.MessageThreadID)
	}
	if !c.body.DisableWebPagePreview {
		t.Error("disable_web_page_preview not set")
	}
	if !strings.HasPrefix(c.body.Text, "[statwatch] NEW major: Abnormal accounts in AP-Jakarta\n\nNEW · major") {
		t.Errorf("unexpected text:\n%s", c.body.Text)
	}
}

func TestSendClassifiesResponses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		reply     string
		want      error
		wantAfter time.Duration
	}{
		{name: "ok", status: 200, reply: `{"ok":true}`, want: nil},
		{name: "200 but ok false is permanent", status: 200, reply: `{"ok":false,"description":"weird"}`, want: notify.ErrPermanent},
		{name: "bad token", status: 401, reply: `{"ok":false,"description":"Unauthorized"}`, want: notify.ErrPermanent},
		{name: "bot blocked", status: 403, reply: `{"ok":false,"description":"Forbidden: bot was blocked by the user"}`, want: notify.ErrPermanent},
		{name: "chat not found", status: 400, reply: `{"ok":false,"description":"Bad Request: chat not found"}`, want: notify.ErrPermanent},
		{name: "rate limited", status: 429, reply: `{"ok":false,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`, want: notify.ErrTransient, wantAfter: 7 * time.Second},
		{name: "server error", status: 502, reply: `<html>bad gateway</html>`, want: notify.ErrTransient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := fakeAPI(t, tc.status, tc.reply)
			n, _ := New("x", testToken, "1", WithBaseURL(srv.URL))
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
			if tc.wantAfter > 0 {
				var rl *notify.RateLimited
				if !errors.As(err, &rl) {
					t.Fatalf("got %T, want *notify.RateLimited", err)
				}
				if rl.After != tc.wantAfter {
					t.Errorf("got After %s, want %s", rl.After, tc.wantAfter)
				}
			}
			// The description must survive so the operator can read why.
			if tc.status != 502 && !strings.Contains(err.Error(), "HTTP") {
				t.Errorf("error lacks HTTP status: %v", err)
			}
		})
	}
}

func TestSendNeverLeaksToken(t *testing.T) {
	// A closed server forces a transport-level *url.Error, which is the
	// path that embeds the full URL (token included) in its message.
	srv, _ := fakeAPI(t, 200, `{"ok":true}`)
	srv.Close()
	n, _ := New("x", testToken, "1", WithBaseURL(srv.URL))
	err := n.Send(context.Background(), testEvent())
	if err == nil {
		t.Fatal("got nil error from closed server")
	}
	if !errors.Is(err, notify.ErrTransient) {
		t.Errorf("got err %v, want ErrTransient", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the bot token: %v", err)
	}
	if !strings.Contains(err.Error(), "<token>") {
		t.Errorf("error should show the redaction marker so it is clear something was scrubbed: %v", err)
	}
}

func TestSendRespectsContext(t *testing.T) {
	srv, _ := fakeAPI(t, 200, `{"ok":true}`)
	n, _ := New("x", testToken, "1", WithBaseURL(srv.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := n.Send(ctx, testEvent())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got err %v, want context.Canceled", err)
	}
}

func TestSendTruncatesByRune(t *testing.T) {
	srv, c := fakeAPI(t, 200, `{"ok":true}`)
	n, _ := New("x", testToken, "1", WithBaseURL(srv.URL))
	ev := testEvent()
	// 5000 CJK runes = 15000 bytes: a byte-based cut would land mid-rune.
	ev.NewUpdates = []incident.Update{{Text: strings.Repeat("修", 5000)}}
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	text := c.body.Text
	c.mu.Unlock()
	if !utf8.ValidString(text) {
		t.Fatal("truncated text is not valid UTF-8")
	}
	if got := utf8.RuneCountInString(text); got > maxTextRunes {
		t.Errorf("got %d runes, want <= %d", got, maxTextRunes)
	}
	if !strings.HasSuffix(text, truncatedMarker) {
		t.Errorf("truncated text lacks marker; tail: %q", text[len(text)-40:])
	}
	if !strings.HasPrefix(text, "[statwatch] NEW major") {
		t.Error("truncation dropped the subject")
	}
}

func TestTruncateExactBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{name: "under", in: "abc", limit: 5, want: "abc"},
		{name: "exact", in: "abcde", limit: 5, want: "abcde"},
		{name: "over ascii", in: strings.Repeat("a", 30), limit: 20, want: strings.Repeat("a", 20-utf8.RuneCountInString(truncatedMarker)) + truncatedMarker},
		{name: "over cjk", in: strings.Repeat("修", 30), limit: 20, want: strings.Repeat("修", 20-utf8.RuneCountInString(truncatedMarker)) + truncatedMarker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.in, tc.limit); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
