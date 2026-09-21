// Package telegram delivers events through the Telegram Bot API.
//
// Messages are sent as plain text with no parse_mode. Telegram's Markdown and
// HTML modes reject a message outright when an unescaped character appears,
// and incident text is full of them; a rejected alert is worse than an
// unformatted one.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/notify"
)

// DefaultBaseURL is the public Bot API host.
const DefaultBaseURL = "https://api.telegram.org"

// maxTextRunes is Telegram's hard limit on sendMessage text. It counts
// characters, not bytes, so a CJK incident must be truncated by rune.
const maxTextRunes = 4096

const truncatedMarker = "\n… (truncated)"

// maxResponseBody caps how much of an error reply is read. Error bodies are
// a few hundred bytes; anything larger is not the Bot API talking.
const maxResponseBody = 64 << 10

// Notifier sends to one chat with one bot.
type Notifier struct {
	name     string
	token    string
	chatID   string
	threadID int64
	base     string
	http     *http.Client
	ua       string
}

// Option configures a Notifier.
type Option func(*Notifier)

// WithThreadID targets a forum topic inside a supergroup.
func WithThreadID(id int64) Option { return func(n *Notifier) { n.threadID = id } }

// WithBaseURL overrides the API host. Primarily for tests.
func WithBaseURL(u string) Option { return func(n *Notifier) { n.base = strings.TrimRight(u, "/") } }

// WithHTTPClient replaces the HTTP client. Primarily for tests.
func WithHTTPClient(c *http.Client) Option { return func(n *Notifier) { n.http = c } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(n *Notifier) { n.ua = ua } }

// New builds a Notifier. name is the instance label, token the bot token and
// chatID the numeric chat id or @channelusername.
func New(name, token, chatID string, opts ...Option) (*Notifier, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("%w: telegram %q: empty bot token", notify.ErrPermanent, name)
	}
	if strings.TrimSpace(chatID) == "" {
		return nil, fmt.Errorf("%w: telegram %q: empty chat id", notify.ErrPermanent, name)
	}
	n := &Notifier{
		name:   "telegram/" + name,
		token:  token,
		chatID: chatID,
		base:   DefaultBaseURL,
		http:   &http.Client{Timeout: 30 * time.Second},
		ua:     "statusrelay",
	}
	for _, o := range opts {
		o(n)
	}
	return n, nil
}

func (n *Notifier) Name() string { return n.name }

// sendMessage is the request body. Field names are Telegram's.
type sendMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	MessageThreadID       int64  `json:"message_thread_id,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

// apiResponse is the subset of Telegram's envelope needed to classify a
// failure.
type apiResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Send posts one message. Errors never contain the request URL: the bot token
// is part of the path, and net/http's *url.Error prints the URL verbatim.
func (n *Notifier) Send(ctx context.Context, ev incident.Event) error {
	m := notify.Render(ev)
	body, err := json.Marshal(sendMessage{
		ChatID:                n.chatID,
		Text:                  truncate(m.Subject+"\n\n"+m.Body, maxTextRunes),
		MessageThreadID:       n.threadID,
		DisableWebPagePreview: true,
	})
	if err != nil {
		return fmt.Errorf("%w: encoding message: %v", notify.ErrPermanent, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base+"/bot"+n.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: building request: %v", notify.ErrPermanent, redact(err.Error(), n.token))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", n.ua)

	resp, err := n.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %s", notify.ErrTransient, redact(err.Error(), n.token))
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	var ar apiResponse
	_ = json.Unmarshal(raw, &ar) // a non-JSON body is classified by status below

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && ar.OK:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		after := time.Duration(ar.Parameters.RetryAfter) * time.Second
		return &notify.RateLimited{After: after, Err: fmt.Errorf("telegram: %s", desc(ar, resp))}
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: telegram: %s", notify.ErrTransient, desc(ar, resp))
	default:
		// 400 (bad chat id, message too long), 401/404 (bad token), 403
		// (bot blocked or not in the chat). None of these change on retry.
		return fmt.Errorf("%w: telegram: %s", notify.ErrPermanent, desc(ar, resp))
	}
}

func desc(ar apiResponse, resp *http.Response) string {
	if ar.Description != "" {
		return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, ar.Description)
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// redact scrubs the token from text that net/http may have embedded it in.
func redact(s, token string) string { return strings.ReplaceAll(s, token, "<token>") }

// truncate cuts s to at most limit runes, appending a marker when it does.
// Byte-based slicing would split a multi-byte character and Telegram rejects
// invalid UTF-8 with a 400 — the alert would be lost precisely when it is
// longest and most detailed.
func truncate(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	keep := limit - utf8.RuneCountInString(truncatedMarker)
	var b strings.Builder
	for _, r := range s {
		if keep == 0 {
			break
		}
		b.WriteRune(r)
		keep--
	}
	b.WriteString(truncatedMarker)
	return b.String()
}
