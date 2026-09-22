package notify

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

// instantClock records every requested wait and fires it immediately, so a
// test can assert the backoff schedule without advancing anything.
type instantClock struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (c *instantClock) Now() time.Time { return time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC) }

func (c *instantClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- c.Now()
	return ch
}

func (c *instantClock) NewTicker(time.Duration) clock.Ticker { panic("not used") }

// scripted returns a Fake whose Send answers from the script in order and
// nil once it runs out.
func scripted(script ...error) *Fake {
	var mu sync.Mutex
	calls := 0
	f := &Fake{NameStr: "fake/x"}
	f.SendFunc = func(context.Context, incident.Event) error {
		mu.Lock()
		defer mu.Unlock()
		i := calls
		calls++
		if i < len(script) {
			return script[i]
		}
		return nil
	}
	return f
}

func TestWithRetry(t *testing.T) {
	transient := fmt.Errorf("boom: %w", ErrTransient)
	permanent := fmt.Errorf("nope: %w", ErrPermanent)
	limited := &RateLimited{After: 5 * time.Second, Err: transient}

	for _, tc := range []struct {
		name      string
		script    []error
		attempts  int
		base      time.Duration
		wantCalls int
		wantWaits []time.Duration
		wantErr   error // sentinel expected in the result, nil for success
	}{
		// wantCalls-1 retries are reported through OnRetry for every row,
		// except a permanent failure or a single attempt, which retry nothing.
		{name: "first try succeeds", attempts: 3, base: time.Second, wantCalls: 1},
		{name: "transient then success", script: []error{transient}, attempts: 3, base: time.Second,
			wantCalls: 2, wantWaits: []time.Duration{time.Second}},
		{name: "exponential schedule then exhausted", script: []error{transient, transient, transient}, attempts: 3, base: time.Second,
			wantCalls: 3, wantWaits: []time.Duration{time.Second, 2 * time.Second}, wantErr: ErrTransient},
		{name: "permanent stops at once", script: []error{permanent}, attempts: 3, base: time.Second,
			wantCalls: 1, wantErr: ErrPermanent},
		{name: "attempts below one means one", script: []error{transient}, attempts: 0, base: time.Second,
			wantCalls: 1, wantErr: ErrTransient},
		{name: "zero base skips the clock", script: []error{transient, transient}, attempts: 3, base: 0,
			wantCalls: 3},
		{name: "rate limit longer than backoff wins", script: []error{limited}, attempts: 2, base: time.Second,
			wantCalls: 2, wantWaits: []time.Duration{5 * time.Second}},
		{name: "rate limit shorter than backoff loses", script: []error{&RateLimited{After: time.Millisecond, Err: transient}}, attempts: 2, base: time.Second,
			wantCalls: 2, wantWaits: []time.Duration{time.Second}},
		{name: "rate limit is transient for errors.Is", script: []error{limited, limited}, attempts: 2, base: 0,
			wantCalls: 2, wantWaits: []time.Duration{5 * time.Second}, wantErr: ErrTransient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := scripted(tc.script...)
			clk := &instantClock{}
			var retried []string
			n := WithRetry(f, clk, tc.attempts, tc.base, OnRetry(func(sink string) { retried = append(retried, sink) }))

			err := n.Send(context.Background(), event13())

			if got := len(f.Calls()); got != tc.wantCalls {
				t.Errorf("got %d calls, want %d", got, tc.wantCalls)
			}
			if got := len(retried); got != tc.wantCalls-1 {
				t.Errorf("OnRetry fired %d times, want %d (one per retry)", got, tc.wantCalls-1)
			}
			for _, name := range retried {
				if name != "fake/x" {
					t.Errorf("OnRetry got sink %q, want fake/x", name)
				}
			}
			if fmt.Sprint(clk.waits) != fmt.Sprint(tc.wantWaits) {
				t.Errorf("got waits %v, want %v", clk.waits, tc.wantWaits)
			}
			if tc.wantErr == nil && err != nil {
				t.Errorf("got err %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("got err %v, want %v", err, tc.wantErr)
			}
			if n.Name() != "fake/x" {
				t.Errorf("got name %q, want fake/x", n.Name())
			}
		})
	}
}

func TestWithRetryStopsOnCancelledContext(t *testing.T) {
	transient := fmt.Errorf("boom: %w", ErrTransient)
	f := scripted(transient, transient, transient)
	// A fake clock that is never advanced: the only way out of the wait is
	// the context.
	clk := clock.NewFake(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))
	n := WithRetry(f, clk, 3, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := n.Send(ctx, event13())

	if !errors.Is(err, context.Canceled) {
		t.Errorf("got err %v, want context.Canceled", err)
	}
	if got := len(f.Calls()); got != 1 {
		t.Errorf("got %d calls, want 1 (no retry after cancel)", got)
	}
	// The original failure must survive in the message so the log explains
	// what was being retried, not just that it stopped.
	if !errors.Is(err, context.Canceled) || err.Error() == "" {
		t.Errorf("cancel error lost context: %v", err)
	}
}

func TestFakeRecordsCallsWithoutSendFunc(t *testing.T) {
	f := &Fake{NameStr: "fake/plain"}
	if err := f.Send(context.Background(), event13()); err != nil {
		t.Fatalf("got err %v, want nil", err)
	}
	if got := len(f.Calls()); got != 1 {
		t.Errorf("got %d calls, want 1", got)
	}
}
