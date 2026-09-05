package clock

import (
	"sync"
	"time"
)

// Fake is a deterministic Clock for tests. Time only advances when a test calls
// Advance, so a test asserting "after fifteen minutes of failures we alert"
// costs nothing and cannot flake.
//
// It lives in the non-test file so every package can use it without importing
// a _test package.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	tickers []*fakeTicker
}

// NewFake returns a Fake started at the given instant. Pass a fixed literal
// rather than time.Now() so failures are reproducible.
func NewFake(start time.Time) *Fake { return &Fake{now: start} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After returns a channel that fires once the fake clock passes d. An Advance
// large enough to cover d delivers immediately.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{ch: ch, interval: d, next: f.now.Add(d), once: true}
	f.tickers = append(f.tickers, t)
	return ch
}

func (f *Fake) NewTicker(d time.Duration) Ticker {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{ch: make(chan time.Time, 1), interval: d, next: f.now.Add(d)}
	f.tickers = append(f.tickers, t)
	return t
}

// Advance moves the clock forward and fires every ticker whose deadline passed.
// Sends are non-blocking: a ticker whose buffer is full drops the tick, exactly
// as time.Ticker does, so a slow consumer cannot deadlock a test.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now
	tickers := make([]*fakeTicker, len(f.tickers))
	copy(tickers, f.tickers)
	f.mu.Unlock()

	for _, t := range tickers {
		t.fireUpTo(now)
	}
}

type fakeTicker struct {
	mu       sync.Mutex
	ch       chan time.Time
	interval time.Duration
	next     time.Time
	once     bool
	stopped  bool
	fired    bool
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
}

func (t *fakeTicker) fireUpTo(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped || t.interval <= 0 {
		return
	}
	for !t.next.After(now) {
		if t.once && t.fired {
			return
		}
		select {
		case t.ch <- t.next:
		default:
		}
		t.fired = true
		if t.once {
			return
		}
		t.next = t.next.Add(t.interval)
	}
}
