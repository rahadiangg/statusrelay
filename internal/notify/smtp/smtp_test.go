package smtp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	gosmtp "net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/notify"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

var testEpoch = time.Date(2026, 9, 21, 10, 30, 0, 0, time.UTC)

// fakeRelay is a minimal loopback SMTP server: enough of the dialogue for
// net/smtp to complete one message, with hooks to fail specific verbs.
//
// PLAIN over plaintext is permitted by net/smtp only for localhost, which is
// exactly where this listens, so auth can be exercised without TLS.
type fakeRelay struct {
	ln    net.Listener
	reply map[string]string // verb -> canned failure line, e.g. "RCPT" -> "550 no such user"

	mu   sync.Mutex
	data string
	from string
	to   []string
	auth string
}

func newFakeRelay(t *testing.T, reply map[string]string) *fakeRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRelay{ln: ln, reply: reply}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeRelay) addr() string { return f.ln.Addr().String() }

func (f *fakeRelay) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.session(c)
	}
}

func (f *fakeRelay) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	w := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	w("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		if fail, ok := f.reply[verb]; ok {
			w(fail)
			continue
		}
		switch verb {
		case "EHLO":
			w("250-fake")
			w("250-AUTH PLAIN")
			w("250 8BITMIME")
		case "AUTH":
			f.mu.Lock()
			f.auth = line
			f.mu.Unlock()
			w("235 ok")
		case "MAIL":
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			w("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.to = append(f.to, line)
			f.mu.Unlock()
			w("250 ok")
		case "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			w("250 queued")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("500 what")
		}
	}
}

func (f *fakeRelay) captured() (data, from string, to []string, auth string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data, f.from, append([]string(nil), f.to...), f.auth
}

func testEvent(kind incident.EventKind) incident.Event {
	r := incident.Record{
		Key:       incident.Key{SourceID: "huawei-intl", ProviderID: "13"},
		Title:     "亚太-雅加达 ECS anomaly: <b>不是</b> markup",
		Severity:  incident.SeverityMajor,
		Status:    incident.StatusOpen,
		StartedAt: time.Date(2026, 7, 25, 19, 5, 0, 0, time.UTC),
		Scope:     []incident.Scope{{RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta", Services: []incident.Service{{Abbr: "ECS"}}}},
		Updates:   []incident.Update{{At: time.Date(2026, 7, 25, 19, 5, 0, 0, time.UTC), Text: strings.Repeat("尊敬的华为云客户，", 40)}},
	}
	r.FP = incident.Compute(r)
	return incident.Event{Kind: kind, Record: r, NewUpdates: r.Updates}
}

func newTestNotifier(t *testing.T, relay *fakeRelay, opts ...Option) *Notifier {
	t.Helper()
	base := []Option{WithClock(clock.NewFake(testEpoch)), WithUserAgent("statwatch/test")}
	n, err := New("ops", relay.addr(), "StatWatch <bot@example.com>",
		[]string{"On Call <oncall@example.com>", "sre@example.com"}, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return n
}

func TestNewValidatesConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		from string
		to   []string
	}{
		{name: "addr without port", addr: "mail.example.com", from: "a@b.c", to: []string{"x@y.z"}},
		{name: "bad from", addr: "h:25", from: "not an address", to: []string{"x@y.z"}},
		{name: "no recipients", addr: "h:25", from: "a@b.c", to: nil},
		{name: "bad recipient", addr: "h:25", from: "a@b.c", to: []string{"x@y.z", "@@"}},
		{name: "header injection in from", addr: "h:25", from: "a@b.c\r\nBcc: e@f.g", to: []string{"x@y.z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("x", tc.addr, tc.from, tc.to)
			if !errors.Is(err, notify.ErrPermanent) {
				t.Errorf("got err %v, want ErrPermanent", err)
			}
		})
	}
}

func TestSendDeliversWellFormedMessage(t *testing.T) {
	relay := newFakeRelay(t, nil)
	n := newTestNotifier(t, relay, WithAuth("bot", "hunter2"))
	if got := n.Name(); got != "smtp/ops" {
		t.Errorf("got name %q, want smtp/ops", got)
	}
	ev := testEvent(incident.KindNew)
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send: %v", err)
	}

	data, from, to, auth := relay.captured()
	if from != "MAIL FROM:<bot@example.com> BODY=8BITMIME" && from != "MAIL FROM:<bot@example.com>" {
		t.Errorf("envelope from: got %q", from)
	}
	if len(to) != 2 || to[0] != "RCPT TO:<oncall@example.com>" || to[1] != "RCPT TO:<sre@example.com>" {
		t.Errorf("envelope to: got %q", to)
	}
	if !strings.HasPrefix(auth, "AUTH PLAIN ") {
		t.Errorf("auth: got %q, want PLAIN", auth)
	}

	msg, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("message does not parse: %v\n%s", err, data)
	}
	h := msg.Header
	dec := new(mime.WordDecoder)
	subject, err := dec.DecodeHeader(h.Get("Subject"))
	if err != nil {
		t.Fatalf("subject decode: %v", err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"From", h.Get("From"), `"StatWatch" <bot@example.com>`},
		{"To", h.Get("To"), `"On Call" <oncall@example.com>, <sre@example.com>`},
		{"Subject", subject, "[statwatch] NEW major: 亚太-雅加达 ECS anomaly: <b>不是</b> markup"},
		{"Date", h.Get("Date"), "Mon, 21 Sep 2026 10:30:00 +0000"},
		{"Message-ID", h.Get("Message-ID"), "<" + notify.ThreadID(ev.Record.Key) + "@statwatch>"},
		{"Content-Type", h.Get("Content-Type"), "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", h.Get("Content-Transfer-Encoding"), "quoted-printable"},
		{"X-Mailer", h.Get("X-Mailer"), "statwatch/test"},
		{"X-Statwatch-Event-Kind", h.Get("X-Statwatch-Event-Kind"), "new"},
		{"In-Reply-To (opener has none)", h.Get("In-Reply-To"), ""},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	// Subject must be pure ASCII on the wire.
	for _, r := range h.Get("Subject") {
		if r > 127 {
			t.Fatalf("subject not RFC 2047 encoded: %q", h.Get("Subject"))
		}
	}

	// Every raw line must fit the SMTP limit, and the body must round-trip.
	for i, line := range strings.Split(data, "\r\n") {
		if len(line) > 998 {
			t.Errorf("line %d is %d octets, exceeds 998", i, len(line))
		}
	}
	body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatalf("qp decode: %v", err)
	}
	// net/smtp's DATA writer canonicalises bare LF to CRLF on the wire, so
	// compare after undoing that; the text itself must be untouched.
	want := notify.Render(ev).Body
	if got := strings.ReplaceAll(string(body), "\r\n", "\n"); got != want {
		t.Errorf("body round-trip mismatch\n--- got ---\n%s\n--- want ---\n%s", body, want)
	}
	if strings.Contains(data, "\n.\r\n") {
		t.Error("a bare dot line survived into DATA; net/smtp dot-stuffing was bypassed")
	}
}

func TestSendThreadsFollowUps(t *testing.T) {
	relay := newFakeRelay(t, nil)
	n := newTestNotifier(t, relay)
	ev := testEvent(incident.KindResolved)
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	data, _, _, auth := relay.captured()
	if auth != "" {
		t.Errorf("auth attempted without credentials: %q", auth)
	}
	msg, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	root := "<" + notify.ThreadID(ev.Record.Key) + "@statwatch>"
	own := "<" + notify.EventID(ev) + "@statwatch>"
	for _, tc := range []struct{ name, got, want string }{
		{"Message-ID", msg.Header.Get("Message-ID"), own},
		{"In-Reply-To", msg.Header.Get("In-Reply-To"), root},
		{"References", msg.Header.Get("References"), root},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if own == root {
		t.Error("follow-up reused the thread root as its own id")
	}
}

func TestSendClassifiesRelayReplies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply map[string]string
		want  error
	}{
		{name: "greylisted at RCPT", reply: map[string]string{"RCPT": "451 4.7.1 try again later"}, want: notify.ErrTransient},
		{name: "mailbox busy at DATA", reply: map[string]string{"DATA": "450 busy"}, want: notify.ErrTransient},
		{name: "auth rejected", reply: map[string]string{"AUTH": "535 5.7.8 bad credentials"}, want: notify.ErrPermanent},
		{name: "relay denied", reply: map[string]string{"RCPT": "550 5.7.1 relaying denied"}, want: notify.ErrPermanent},
		{name: "sender rejected", reply: map[string]string{"MAIL": "553 bad sender"}, want: notify.ErrPermanent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relay := newFakeRelay(t, tc.reply)
			n := newTestNotifier(t, relay, WithAuth("bot", "pw"))
			err := n.Send(context.Background(), testEvent(incident.KindNew))
			if !errors.Is(err, tc.want) {
				t.Errorf("got err %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSendConnectionRefusedIsTransient(t *testing.T) {
	relay := newFakeRelay(t, nil)
	addr := relay.addr()
	_ = relay.ln.Close()
	n, err := New("x", addr, "a@example.com", []string{"b@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), testEvent(incident.KindNew))
	if !errors.Is(err, notify.ErrTransient) {
		t.Errorf("got err %v, want ErrTransient", err)
	}
}

func TestSendHonoursCancelledContext(t *testing.T) {
	called := false
	n, _ := New("x", "127.0.0.1:1", "a@example.com", []string{"b@example.com"},
		WithSendMail(func(string, gosmtp.Auth, string, []string, []byte) error { called = true; return nil }))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.Send(ctx, testEvent(incident.KindNew)); !errors.Is(err, context.Canceled) {
		t.Errorf("got err %v, want context.Canceled", err)
	}
	if called {
		t.Error("sendMail called despite cancelled context")
	}
}

func TestClassifyUnencryptedPlainIsPermanent(t *testing.T) {
	// net/smtp's own refusal text for PLAIN without TLS off-localhost.
	err := classify(errors.New("unencrypted connection"))
	if !errors.Is(err, notify.ErrPermanent) {
		t.Errorf("got %v, want ErrPermanent", err)
	}
	err = classify(&textproto.Error{Code: 421, Msg: "closing"})
	if !errors.Is(err, notify.ErrTransient) {
		t.Errorf("got %v, want ErrTransient", err)
	}
	err = classify(fmt.Errorf("wrapped: %w", &textproto.Error{Code: 554, Msg: "no"}))
	if !errors.Is(err, notify.ErrPermanent) {
		t.Errorf("got %v, want ErrPermanent", err)
	}
}
