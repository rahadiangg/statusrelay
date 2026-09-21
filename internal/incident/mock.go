package incident

import (
	"context"
	"sync"
)

// FakeSource is a hand-written Source for tests in other packages. Unset
// funcs return an empty complete snapshot and a passing self-check.
//
// It lives in a non-test file so the poller's tests can use it without a
// second copy of the contract.
type FakeSource struct {
	IDStr         string
	FetchFunc     func(ctx context.Context) (*Snapshot, error)
	SelfCheckFunc func(ctx context.Context) error

	mu         sync.Mutex
	fetches    int
	selfChecks int
}

func (f *FakeSource) ID() string   { return f.IDStr }
func (f *FakeSource) Kind() string { return "fake" }

func (f *FakeSource) Capabilities() Capabilities { return Capabilities{} }

func (f *FakeSource) Fetch(ctx context.Context) (*Snapshot, error) {
	f.mu.Lock()
	f.fetches++
	f.mu.Unlock()
	if f.FetchFunc == nil {
		return &Snapshot{SourceID: f.IDStr, Complete: true, UnresolvedCount: 0}, nil
	}
	return f.FetchFunc(ctx)
}

func (f *FakeSource) SelfCheck(ctx context.Context) error {
	f.mu.Lock()
	f.selfChecks++
	f.mu.Unlock()
	if f.SelfCheckFunc == nil {
		return nil
	}
	return f.SelfCheckFunc(ctx)
}

// Fetches returns how many times Fetch was called.
func (f *FakeSource) Fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

// SelfChecks returns how many times SelfCheck was called.
func (f *FakeSource) SelfChecks() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.selfChecks
}

var _ Source = (*FakeSource)(nil)
