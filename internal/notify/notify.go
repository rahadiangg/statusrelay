// Package notify defines the transport contract and the pieces every
// transport shares: the plain-text renderer, deterministic event identifiers,
// and the retry decorator.
//
// Transports live in subpackages (telegram, smtp, webhook). They are
// deliberately thin: one Send, one classification of the remote's answer into
// ErrTransient or ErrPermanent, nothing else. Everything a transport could get
// subtly wrong on its own — what the message says, how retries pace, how a
// receiver dedupes — is decided here once.
//
// Delivery is at-least-once. A retry after a send that actually succeeded is
// a duplicate, and the fix for that is the receiver deduping on EventID, not
// this package pretending it can know.
package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

// Notifier delivers one event over one transport.
//
// Send must be safe to call concurrently, must respect ctx, and must classify
// its failure as ErrTransient or ErrPermanent. A fan-out caller must treat
// every Notifier independently: one transport failing is never a reason to
// skip the others.
type Notifier interface {
	// Name is the instance label for logs and metrics, e.g. "telegram/oncall".
	Name() string
	Send(ctx context.Context, ev incident.Event) error
}

// EventID identifies one delivery deterministically.
//
// It covers the record key, the event kind, and the three fingerprint hashes,
// so a retried delivery of the same transition produces the same id (a
// receiver can dedupe) while a second progress entry on the same record
// produces a different one (it is genuinely new information).
func EventID(ev incident.Event) string {
	h := sha256.New()
	for _, s := range []string{
		ev.Record.Key.SourceID, ev.Record.Key.ProviderID, string(ev.Kind),
		ev.Record.FP.Content, ev.Record.FP.Scope, ev.Record.FP.Progress,
	} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ThreadID identifies an incident across its whole lifecycle, so a mail client
// or a chat receiver can group new/updated/resolved into one conversation.
func ThreadID(k incident.Key) string {
	h := sha256.Sum256([]byte(k.SourceID + "\x00" + k.ProviderID))
	return hex.EncodeToString(h[:])[:16]
}

// WithRetry wraps n so transient failures are retried with exponential
// backoff, paced by clk so tests never sleep.
//
// attempts is the total number of tries, so attempts <= 1 disables retry.
// A RateLimited error's After overrides the backoff when it is longer. A
// permanent error or a cancelled ctx stops immediately; the last error is
// returned wrapped, never swallowed — an alert that could not be delivered
// must be visible to whoever reads the logs.
func WithRetry(n Notifier, clk clock.Clock, attempts int, base time.Duration, opts ...RetryOption) Notifier {
	if attempts < 1 {
		attempts = 1
	}
	r := &retrier{n: n, clk: clk, attempts: attempts, base: base}
	for _, o := range opts {
		o(r)
	}
	return r
}

// RetryOption configures WithRetry.
type RetryOption func(*retrier)

// OnRetry is called with the sink name each time a failed attempt is about
// to be retried. A delivery that succeeds on its third try reports "ok"; this
// is how a flapping relay stays visible.
func OnRetry(f func(sink string)) RetryOption { return func(r *retrier) { r.onRetry = f } }

type retrier struct {
	n        Notifier
	clk      clock.Clock
	attempts int
	base     time.Duration
	onRetry  func(sink string)
}

func (r *retrier) Name() string { return r.n.Name() }

func (r *retrier) Send(ctx context.Context, ev incident.Event) error {
	var last error
	for attempt := 0; attempt < r.attempts; attempt++ {
		err := r.n.Send(ctx, ev)
		if err == nil {
			return nil
		}
		last = err
		if !errors.Is(err, ErrTransient) || attempt == r.attempts-1 {
			break
		}
		if r.onRetry != nil {
			r.onRetry(r.n.Name())
		}
		wait := r.base * time.Duration(1<<attempt)
		var rl *RateLimited
		if errors.As(err, &rl) && rl.After > wait {
			wait = rl.After
		}
		// A zero wait must not touch the clock: a fake clock's After(0) never
		// fires, and a real one is a pointless goroutine.
		if wait <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: giving up after %d attempt(s): %w (last error: %v)",
				r.n.Name(), attempt+1, ctx.Err(), last)
		case <-r.clk.After(wait):
		}
	}
	return fmt.Errorf("%s: %w", r.n.Name(), last)
}
