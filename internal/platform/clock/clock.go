// Package clock provides an injectable time source.
//
// Every scheduling decision in this service is time-dependent (poll cadence,
// failure thresholds, "has the loop gone stale"), and a test that proves those
// decisions by sleeping is both slow and flaky. Nothing outside main may call
// time.Now or time.NewTicker directly; take a Clock instead.
package clock

import "time"

// Clock is the subset of the time package this service is allowed to use.
type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
	// After is used for timeouts inside select statements.
	After(d time.Duration) <-chan time.Time
}

// Ticker mirrors *time.Ticker so Fake can substitute for it.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// System is the real clock. Use it everywhere except tests.
type System struct{}

func (System) Now() time.Time { return time.Now() }

func (System) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (System) NewTicker(d time.Duration) Ticker { return &systemTicker{t: time.NewTicker(d)} }

type systemTicker struct{ t *time.Ticker }

func (s *systemTicker) C() <-chan time.Time { return s.t.C }
func (s *systemTicker) Stop()               { s.t.Stop() }
