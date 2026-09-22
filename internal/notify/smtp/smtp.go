// Package smtp delivers events as plain-text email through net/smtp.
//
// It supports the common relay shape only: port 587, STARTTLS when the server
// offers it, PLAIN auth when credentials are configured. net/smtp refuses
// PLAIN over an unencrypted connection to anything but localhost, and that
// refusal is kept: a relay that silently downgrades would leak the password.
//
// Every event of one incident shares a References header, so a mail client
// threads new/updated/resolved into one conversation rather than scattering
// them across the inbox.
package smtp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/notify"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

// SendMailFunc mirrors net/smtp.SendMail so tests can substitute it.
type SendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

// Notifier sends to a fixed recipient list through one relay.
type Notifier struct {
	name     string
	addr     string
	from     *mail.Address
	to       []*mail.Address
	auth     smtp.Auth
	clock    clock.Clock
	sendMail SendMailFunc
	ua       string
	render   notify.Renderer
}

// Option configures a Notifier.
type Option func(*Notifier)

// WithAuth enables PLAIN authentication. host is derived from the relay
// address; net/smtp checks it against the TLS certificate.
func WithAuth(user, pass string) Option {
	return func(n *Notifier) {
		host, _, _ := net.SplitHostPort(n.addr)
		n.auth = smtp.PlainAuth("", user, pass, host)
	}
}

// WithClock injects the time source used for the Date header.
func WithClock(c clock.Clock) Option { return func(n *Notifier) { n.clock = c } }

// WithSendMail replaces the delivery function. Primarily for tests.
func WithSendMail(f SendMailFunc) Option { return func(n *Notifier) { n.sendMail = f } }

// WithUserAgent sets the X-Mailer header.
func WithUserAgent(ua string) Option { return func(n *Notifier) { n.ua = ua } }

// WithRenderer sets how events are turned into text (timezone, provider
// names). The zero Renderer is UTC with raw source ids.
func WithRenderer(r notify.Renderer) Option { return func(n *Notifier) { n.render = r } }

// New builds a Notifier. addr is host:port; from and to are RFC 5322
// addresses, display names allowed.
//
// Recipients are parsed here, not at send time, so a typo in config fails at
// startup rather than on the first real incident.
func New(name, addr, from string, to []string, opts ...Option) (*Notifier, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("%w: smtp %q: relay address %q: %v", notify.ErrPermanent, name, addr, err)
	}
	fromAddr, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("%w: smtp %q: from address %q: %v", notify.ErrPermanent, name, from, err)
	}
	if len(to) == 0 {
		return nil, fmt.Errorf("%w: smtp %q: no recipients", notify.ErrPermanent, name)
	}
	toAddrs := make([]*mail.Address, 0, len(to))
	for _, t := range to {
		a, err := mail.ParseAddress(t)
		if err != nil {
			return nil, fmt.Errorf("%w: smtp %q: recipient %q: %v", notify.ErrPermanent, name, t, err)
		}
		toAddrs = append(toAddrs, a)
	}
	n := &Notifier{
		name:     "smtp/" + name,
		addr:     addr,
		from:     fromAddr,
		to:       toAddrs,
		clock:    clock.System{},
		sendMail: smtp.SendMail,
		ua:       "statusrelay",
	}
	for _, o := range opts {
		o(n)
	}
	return n, nil
}

func (n *Notifier) Name() string { return n.name }

// Send builds and delivers one message.
//
// net/smtp.SendMail takes no context. The ctx is honoured before dialling and
// the dial itself is bounded by the relay's own timeouts; a cancelled ctx
// mid-transaction lets the current message finish rather than leaving the
// relay with a half-sent DATA block.
func (n *Notifier) Send(ctx context.Context, ev incident.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	msg, err := n.build(ev)
	if err != nil {
		return err
	}
	rcpts := make([]string, len(n.to))
	for i, a := range n.to {
		rcpts[i] = a.Address
	}
	if err := n.sendMail(n.addr, n.auth, n.from.Address, rcpts, msg); err != nil {
		return classify(err)
	}
	return nil
}

// build renders the RFC 5322 message with CRLF line endings.
func (n *Notifier) build(ev incident.Event) ([]byte, error) {
	m := n.render.Render(ev)

	tos := make([]string, len(n.to))
	for i, a := range n.to {
		tos[i] = a.String()
	}
	// The opening message IS the thread root; every later event replies to
	// it. A client that never saw the opener still groups by References.
	root := "<" + notify.ThreadID(ev.Record.Key) + "@statusrelay>"
	msgID := "<" + notify.EventID(ev) + "@statusrelay>"
	if ev.Kind == incident.KindNew {
		msgID = root
	}

	headers := [][2]string{
		{"From", n.from.String()},
		{"To", strings.Join(tos, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", m.Subject)},
		{"Date", n.clock.Now().UTC().Format(time.RFC1123Z)},
		{"Message-ID", msgID},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"X-Mailer", n.ua},
		{"X-Statusrelay-Event-Kind", string(ev.Kind)},
	}
	if ev.Kind != incident.KindNew {
		headers = append(headers, [2]string{"In-Reply-To", root}, [2]string{"References", root})
	}

	var b bytes.Buffer
	for _, h := range headers {
		// Render already collapses the subject to one line and the rest are
		// ours, but a header injection is the one email bug that turns a
		// notifier into a spam relay, so the check is structural.
		if strings.ContainsAny(h[1], "\r\n") {
			return nil, fmt.Errorf("%w: header %s contains a line break", notify.ErrPermanent, h[0])
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")

	// Quoted-printable keeps every line under 76 octets. Incident text is
	// multi-paragraph CJK; a raw UTF-8 paragraph blows past the 998-octet SMTP
	// line limit and some relays truncate rather than reject.
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(m.Body)); err != nil {
		return nil, fmt.Errorf("%w: encoding body: %v", notify.ErrPermanent, err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("%w: encoding body: %v", notify.ErrPermanent, err)
	}
	return b.Bytes(), nil
}

// classify maps an SMTP failure onto the shared sentinels.
//
// SMTP reply codes carry the distinction themselves: 4xx is "try again later"
// (greylisting, mailbox busy), 5xx is "never" (auth rejected, relay denied,
// no such user). Anything that is not a reply code is a transport problem.
func classify(err error) error {
	if te, ok := errors.AsType[*textproto.Error](err); ok {
		if te.Code >= 500 {
			return fmt.Errorf("%w: smtp: %v", notify.ErrPermanent, err)
		}
		return fmt.Errorf("%w: smtp: %v", notify.ErrTransient, err)
	}
	// net/smtp reports "unencrypted connection" for PLAIN without TLS as a
	// plain error; it is a configuration fault, not weather.
	if strings.Contains(err.Error(), "unencrypted connection") {
		return fmt.Errorf("%w: smtp: %v", notify.ErrPermanent, err)
	}
	return fmt.Errorf("%w: smtp: %v", notify.ErrTransient, err)
}
