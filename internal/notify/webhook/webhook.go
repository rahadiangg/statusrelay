// Package webhook delivers events as one JSON document per POST.
//
// The payload is versioned and its field names are stable across releases:
// receivers are other people's code, and renaming a field is an outage for
// them that no test here would catch. Add fields; never rename or remove.
//
// A configured secret produces an HMAC-SHA256 over the exact bytes sent, so a
// receiver can prove the post came from this process and was not altered.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/notify"
)

// Schema is the payload version, sent as "schema" in every document.
const Schema = 1

// maxResponseBody caps how much of a reply is read before discarding.
const maxResponseBody = 64 << 10

// Notifier posts to one URL.
type Notifier struct {
	name    string
	url     string
	secret  []byte
	headers map[string]string
	http    *http.Client
	ua      string
}

// Option configures a Notifier.
type Option func(*Notifier)

// WithSecret enables the X-Statwatch-Signature header.
func WithSecret(s string) Option { return func(n *Notifier) { n.secret = []byte(s) } }

// WithHeaders adds fixed request headers, e.g. Authorization. Validated in New.
func WithHeaders(h map[string]string) Option { return func(n *Notifier) { n.headers = h } }

// WithHTTPClient replaces the HTTP client. The redirect policy is reapplied:
// see New for why redirects are refused.
func WithHTTPClient(c *http.Client) Option { return func(n *Notifier) { n.http = c } }

// WithTimeout bounds one delivery attempt.
func WithTimeout(d time.Duration) Option { return func(n *Notifier) { n.http.Timeout = d } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(n *Notifier) { n.ua = ua } }

// New builds a Notifier.
//
// Redirects are never followed. A 3xx would resend the body, the signature and
// any Authorization header to a host the operator did not configure; treating
// it as a failure is the only answer that cannot leak.
func New(name, target string, opts ...Option) (*Notifier, error) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%w: webhook %q: url %q must be absolute http(s)", notify.ErrPermanent, name, target)
	}
	n := &Notifier{
		name: "webhook/" + name,
		url:  u.String(),
		http: &http.Client{Timeout: 30 * time.Second},
		ua:   "statwatch",
	}
	for _, o := range opts {
		o(n)
	}
	n.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for k, v := range n.headers {
		if strings.ContainsAny(k+v, "\r\n") || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("%w: webhook %q: invalid header %q", notify.ErrPermanent, name, k)
		}
	}
	return n, nil
}

func (n *Notifier) Name() string { return n.name }

// Payload is the wire document. Times are RFC 3339 UTC or null.
type Payload struct {
	Schema     int        `json:"schema"`
	EventID    string     `json:"event_id"`
	ThreadID   string     `json:"thread_id"`
	Kind       string     `json:"kind"`
	ColdStart  bool       `json:"cold_start"`
	SourceID   string     `json:"source_id"`
	ProviderID string     `json:"provider_id"`
	Title      string     `json:"title"`
	TitleLang  string     `json:"title_lang"`
	Severity   string     `json:"severity"`
	RawSev     string     `json:"raw_severity"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at"`
	UpdatedAt  *time.Time `json:"updated_at"`
	EndedAt    *time.Time `json:"ended_at"`
	Global     bool       `json:"global"`
	Scope      []Scope    `json:"scope"`
	NewUpdates []Update   `json:"new_updates"`
	Added      []string   `json:"added"`
	Removed    []string   `json:"removed"`
	Subject    string     `json:"subject"`
	Text       string     `json:"text"`
}

// Scope is one affected region.
type Scope struct {
	RegionCode string    `json:"region_code"`
	RegionName string    `json:"region_name"`
	Services   []Service `json:"services"`
}

// Service is one affected product.
type Service struct {
	Abbr string `json:"abbr"`
	Name string `json:"name"`
}

// Update is one progress entry.
type Update struct {
	At   *time.Time `json:"at"`
	Text string     `json:"text"`
	Lang string     `json:"lang"`
}

// Build converts an event into the wire document. Exported so the config
// phase can render a sample and so receivers' tests can construct one.
func Build(ev incident.Event) Payload {
	r := ev.Record
	m := notify.Render(ev)
	p := Payload{
		Schema:     Schema,
		EventID:    notify.EventID(ev),
		ThreadID:   notify.ThreadID(r.Key),
		Kind:       string(ev.Kind),
		ColdStart:  ev.ColdStart,
		SourceID:   r.Key.SourceID,
		ProviderID: r.Key.ProviderID,
		Title:      r.Title,
		TitleLang:  r.TitleLang,
		Severity:   r.Severity.String(),
		RawSev:     r.RawSeverity,
		Status:     r.Status.String(),
		StartedAt:  timePtr(r.StartedAt),
		UpdatedAt:  timePtr(r.UpdatedAt),
		EndedAt:    timePtr(r.EndedAt),
		Global:     r.Global,
		Scope:      []Scope{},
		NewUpdates: []Update{},
		Added:      nonNil(ev.Added),
		Removed:    nonNil(ev.Removed),
		Subject:    m.Subject,
		Text:       m.Body,
	}
	for _, sc := range r.Scope {
		s := Scope{RegionCode: sc.RegionCode, RegionName: sc.RegionName, Services: []Service{}}
		for _, sv := range sc.Services {
			s.Services = append(s.Services, Service{Abbr: sv.Abbr, Name: sv.Name})
		}
		p.Scope = append(p.Scope, s)
	}
	for _, u := range ev.NewUpdates {
		p.NewUpdates = append(p.NewUpdates, Update{At: timePtr(u.At), Text: u.Text, Lang: u.Lang})
	}
	return p
}

// timePtr maps the zero time to null. A zero time serialised as
// "0001-01-01T00:00:00Z" is a value a receiver will happily plot.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// nonNil keeps empty lists as [] rather than null: receivers written in
// stricter languages treat the two differently.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Send posts one event.
func (n *Notifier) Send(ctx context.Context, ev incident.Event) error {
	body, err := json.Marshal(Build(ev))
	if err != nil {
		return fmt.Errorf("%w: encoding payload: %v", notify.ErrPermanent, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: building request: %v", notify.ErrPermanent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", n.ua)
	req.Header.Set("X-Statwatch-Event-Id", notify.EventID(ev))
	req.Header.Set("X-Statwatch-Event-Kind", string(ev.Kind))
	if len(n.secret) > 0 {
		req.Header.Set("X-Statwatch-Signature", "sha256="+Sign(n.secret, body))
	}
	for k, v := range n.headers {
		req.Header.Set(k, v)
	}

	resp, err := n.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: webhook: %v", notify.ErrTransient, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain so the connection is reusable; the content is not ours to act on.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return &notify.RateLimited{After: retryAfter(resp), Err: fmt.Errorf("webhook: HTTP %d", resp.StatusCode)}
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooEarly, resp.StatusCode >= 500:
		return fmt.Errorf("%w: webhook: HTTP %d", notify.ErrTransient, resp.StatusCode)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("%w: webhook: HTTP %d redirect to %q refused; configure the final url",
			notify.ErrPermanent, resp.StatusCode, resp.Header.Get("Location"))
	default:
		return fmt.Errorf("%w: webhook: HTTP %d", notify.ErrPermanent, resp.StatusCode)
	}
}

// Sign returns the hex HMAC-SHA256 of body under secret. Exported so a
// receiver's test can verify a captured request the same way.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// retryAfter reads a delay-seconds Retry-After. The HTTP-date form is rare on
// webhook receivers and a zero result just falls back to normal backoff.
func retryAfter(resp *http.Response) time.Duration {
	s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
	if err != nil || s < 0 {
		return 0
	}
	return time.Duration(s) * time.Second
}
