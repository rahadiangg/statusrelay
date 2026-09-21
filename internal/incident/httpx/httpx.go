// Package httpx is the hardened HTTP client every status adapter shares.
//
// It exists because the upstreams this service reads are undocumented, sit
// behind bot-protection WAFs, and signal failure in ways that a plain
// http.Get plus json.Decode reads as success. Everything here is one of those
// lessons made structural:
//
//   - A JSON endpoint that answers with an HTML challenge page at HTTP 200 must
//     be an error, not an empty result.
//   - A removed endpoint that answers 500 rather than 404 must be a distinct,
//     non-retryable error, or a permanent API removal hides inside transient
//     retry noise for weeks.
//   - A response body must be capped before decoding, so a bad day upstream is
//     a failed poll rather than an OOM kill of the whole watcher.
//   - Redirects must not be followed across hosts or off a path prefix: the
//     prefix is what distinguishes one dataset from another, and following a
//     redirect off it silently returns a different corpus at 200.
package httpx

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// DefaultMaxBody caps the decompressed response. Generous for a status feed
// (the largest real payload observed is ~380KB) and small enough that a
// compression bomb cannot exhaust memory.
const DefaultMaxBody = 8 << 20

// Result carries a decoded response plus the facts callers need for
// change-detection and diagnostics.
type Result struct {
	// Hash is a content hash of the raw body, so a caller can cheaply notice
	// "nothing changed" without re-deriving it from parsed structures.
	Hash string
	// Bytes is the decompressed body, capped at MaxBody.
	Bytes []byte
	// Status is the HTTP status code that produced this result.
	Status int
}

// Client is a hardened JSON fetcher.
type Client struct {
	http      *http.Client
	ua        string
	maxBody   int64
	retries   int
	backoff   time.Duration
	forceIPv4 bool
	headers   map[string]string
}

// Option configures a Client.
type Option func(*Client)

// WithUserAgent sets the User-Agent.
//
// Send something honest and contactable. These endpoints inspect the UA and
// block recognisably hostile ones; spoofing a browser reclassifies a polite
// integration as an evasive bot, which is both worse behaviour and worse
// engineering — you lose the block signal.
func WithUserAgent(ua string) Option { return func(c *Client) { c.ua = ua } }

// WithMaxBody overrides the decompressed body cap.
func WithMaxBody(n int64) Option { return func(c *Client) { c.maxBody = n } }

// WithRetries sets the retry budget for transient failures. Zero disables
// retries, which is what tests want.
func WithRetries(n int) Option { return func(c *Client) { c.retries = n } }

// WithBackoff sets the base retry delay. Tests set it to zero.
func WithBackoff(d time.Duration) Option { return func(c *Client) { c.backoff = d } }

// WithHTTPClient replaces the underlying client entirely. Primarily for tests.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithHeader adds a fixed header to every request.
//
// It exists for Accept-Language: at least one upstream localises product and
// region names server-side from that header and defaults to Chinese without
// it, so a client that cannot send it reconciles configured region names
// against strings the operator cannot read.
func WithHeader(key, value string) Option {
	return func(c *Client) {
		if c.headers == nil {
			c.headers = make(map[string]string)
		}
		c.headers[key] = value
	}
}

// New builds a Client with defaults suited to polling a public status feed.
func New(opts ...Option) *Client {
	c := &Client{
		ua:        "statwatch/dev",
		maxBody:   DefaultMaxBody,
		retries:   2,
		backoff:   500 * time.Millisecond,
		forceIPv4: true,
	}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		c.http = &http.Client{
			Timeout:       30 * time.Second,
			Transport:     newTransport(c.forceIPv4),
			CheckRedirect: refuseUnsafeRedirect,
		}
	}
	return c
}

func newTransport(forceIPv4 bool) *http.Transport {
	network := "tcp"
	if forceIPv4 {
		// Forcing IPv4 is not a preference. Dual-stack Happy-Eyeballs against
		// this upstream produced repeated 75-second TCP *connect* stalls that
		// never reproduced over IPv4, and a 75-second stall inside a
		// two-minute poll loop is indistinguishable from an outage.
		network = "tcp4"
	}
	d := &net.Dialer{
		// Connect timeout is deliberately separate from, and far shorter than,
		// the overall request timeout: a stalled handshake should fail fast and
		// be retried, while a slow but progressing response should be allowed
		// to finish.
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		// Compression is requested explicitly so the cap applies to the
		// decompressed stream; Go's transparent gzip would decompress before we
		// can bound it.
		DisableCompression: true,
	}
}

// refuseUnsafeRedirect blocks any redirect that leaves the host or climbs out
// of the original path prefix.
//
// The path prefix is what selects the dataset on these endpoints. A redirect
// that drops it returns a different site's data at HTTP 200, which no amount of
// downstream validation can distinguish from a healthy response.
func refuseUnsafeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	orig := via[0].URL
	if !strings.EqualFold(req.URL.Host, orig.Host) {
		return fmt.Errorf("%w: redirect to a different host %q", incident.ErrWrongDataset, req.URL.Host)
	}
	if prefix := datasetPrefix(orig.Path); prefix != "" && !strings.HasPrefix(req.URL.Path, prefix) {
		return fmt.Errorf("%w: redirect dropped the %q path prefix", incident.ErrWrongDataset, prefix)
	}
	return nil
}

// datasetPrefix returns the leading path segment, which for these upstreams
// selects which corpus is served.
func datasetPrefix(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i > 0 {
		return "/" + p[:i]
	}
	return ""
}

// GetJSON fetches u and decodes the body into v.
//
// It only ever issues GET. HEAD and OPTIONS are never used: at least one
// upstream answers both with 404 while answering GET with 200, so any health
// check built on them reports a permanent false outage.
func (c *Client) GetJSON(ctx context.Context, u string, v any) (Result, error) {
	var last error
	for attempt := 0; ; attempt++ {
		res, err := c.once(ctx, u, v)
		if err == nil {
			return res, nil
		}
		last = err
		if attempt >= c.retries || !retryable(err) {
			return Result{}, last
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(c.backoff * time.Duration(1<<attempt)):
		}
	}
}

// retryable reports whether an error is worth another attempt.
//
// Only genuinely transient conditions qualify. A WAF block is excluded on
// purpose: retrying into a block deepens it, and a bad-request error is wrong
// rather than unlucky, so retrying just multiplies the same mistake.
func retryable(err error) bool {
	return errors.Is(err, incident.ErrUpstream)
}

func (c *Client) once(ctx context.Context, u string, v any) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Result{}, fmt.Errorf("%w: building request: %v", incident.ErrBadRequest, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", c.ua)
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// A redirect refusal is a dataset error, not a transport hiccup, and
		// must not be retried into the same wrong answer.
		if errors.Is(err, incident.ErrWrongDataset) {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("%w: %v", incident.ErrUpstream, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := c.readBody(resp)
	if err != nil {
		return Result{}, err
	}

	if err := classify(resp, body); err != nil {
		return Result{}, err
	}

	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			// A decode failure must never yield a partial result. Half a
			// payload silently means "fewer incidents than there really are".
			return Result{}, fmt.Errorf("%w: decoding %d bytes: %v", incident.ErrSchemaDrift, len(body), err)
		}
	}

	sum := sha256.Sum256(body)
	return Result{Hash: hex.EncodeToString(sum[:]), Bytes: body, Status: resp.StatusCode}, nil
}

func (c *Client) readBody(resp *http.Response) ([]byte, error) {
	r := io.Reader(resp.Body)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: gzip header: %v", incident.ErrUpstream, err)
		}
		defer func() { _ = zr.Close() }()
		r = zr
	}
	// Read one byte past the cap so an exactly-at-limit body is accepted and an
	// oversized one is detectable rather than silently truncated into invalid
	// JSON — truncation would surface as a confusing parse error instead of the
	// real problem.
	body, err := io.ReadAll(io.LimitReader(r, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %v", incident.ErrUpstream, err)
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", incident.ErrSchemaDrift, c.maxBody)
	}
	return body, nil
}

// upstreamError is the JSON error envelope these APIs use.
type upstreamError struct {
	Code string `json:"error_code"`
	Msg  string `json:"error_msg"`
}

// Upstream error codes with meanings we act on differently.
const (
	// CodeEndpointGone is returned — with HTTP 500, not 404 — when a route no
	// longer exists.
	CodeEndpointGone = "SHD.10010004"
	// CodeBadParameter is returned for malformed query parameters.
	CodeBadParameter = "SHD.0002"
)

// classify turns an HTTP response into one of our sentinel errors.
func classify(resp *http.Response, body []byte) error {
	// A WAF block is identifiable before the status code: the teapot status is
	// this vendor's block signal, and the block id header appears even when the
	// status is otherwise ordinary.
	if resp.StatusCode == http.StatusTeapot || resp.Header.Get("Block-Event-Id") != "" {
		return fmt.Errorf("%w: status %d, block id %q",
			incident.ErrBlocked, resp.StatusCode, resp.Header.Get("Block-Event-Id"))
	}

	if code := errorCode(body); code != "" {
		switch code {
		case CodeEndpointGone:
			// Deliberately mapped ahead of the generic 5xx branch below: this
			// arrives as HTTP 500, and treating it as transient would hide a
			// permanent removal behind retry noise indefinitely.
			return fmt.Errorf("%w: upstream reports %s", incident.ErrEndpointGone, code)
		case CodeBadParameter:
			return fmt.Errorf("%w: upstream reports %s", incident.ErrBadRequest, code)
		}
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		// Fall through to the content check below.
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: status %d", incident.ErrUpstream, resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w: status %d", incident.ErrUpstream, resp.StatusCode)
	default:
		return fmt.Errorf("%w: status %d", incident.ErrBadRequest, resp.StatusCode)
	}

	// HTTP 200 with an HTML body is the signature of a challenge or error page
	// served in place of the API. Decoding it would fail confusingly; treating
	// it as an empty result would be catastrophic.
	if looksLikeHTML(body) {
		return fmt.Errorf("%w: HTML body at status 200", incident.ErrNotJSON)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		return fmt.Errorf("%w: content-type %q", incident.ErrNotJSON, ct)
	}
	return nil
}

func errorCode(body []byte) string {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return ""
	}
	var e upstreamError
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	return e.Code
}

func looksLikeHTML(body []byte) bool {
	t := strings.TrimLeft(string(body), " \t\r\n\ufeff")
	if t == "" {
		return false
	}
	if t[0] != '<' {
		return false
	}
	lower := strings.ToLower(t)
	return strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") || strings.HasPrefix(lower, "<")
}

func isJSONContentType(ct string) bool {
	base, _, _ := strings.Cut(ct, ";")
	base = strings.TrimSpace(strings.ToLower(base))
	return base == "application/json" || strings.HasSuffix(base, "+json") ||
		base == "text/json" || base == "application/javascript"
}

// JoinPath appends a relative path and query to a base URL without ever
// dropping the base path prefix.
//
// url.Parse-and-replace is the usual way this goes wrong: resolving "/v1/x"
// against "https://host/intl" yields "https://host/v1/x", silently selecting a
// different dataset.
func JoinPath(base, rel string, q url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%w: base url %q: %v", incident.ErrBadRequest, base, err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.TrimPrefix(rel, "/")
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}
