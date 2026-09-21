package notify

import (
	"context"
	"sync"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// Fake is a hand-written Notifier for tests in this and other packages.
// It lives in a non-test file so the poller's tests can use it.
type Fake struct {
	NameStr  string
	SendFunc func(ctx context.Context, ev incident.Event) error

	mu    sync.Mutex
	calls []incident.Event
}

func (f *Fake) Name() string { return f.NameStr }

func (f *Fake) Send(ctx context.Context, ev incident.Event) error {
	f.mu.Lock()
	f.calls = append(f.calls, ev)
	f.mu.Unlock()
	if f.SendFunc == nil {
		return nil
	}
	return f.SendFunc(ctx, ev)
}

// Calls returns a copy of every event passed to Send, in order.
func (f *Fake) Calls() []incident.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]incident.Event(nil), f.calls...)
}
