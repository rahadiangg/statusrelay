package clock

import (
	"testing"
	"time"
)

var epoch = time.Date(2026, 7, 26, 2, 5, 0, 0, time.UTC)

func TestFakeNowAdvances(t *testing.T) {
	f := NewFake(epoch)
	if got := f.Now(); !got.Equal(epoch) {
		t.Fatalf("got %v, want %v", got, epoch)
	}
	f.Advance(90 * time.Second)
	if got, want := f.Now(), epoch.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFakeTickerFiresOncePerInterval(t *testing.T) {
	f := NewFake(epoch)
	tk := f.NewTicker(120 * time.Second)
	defer tk.Stop()

	select {
	case <-tk.C():
		t.Fatal("ticker fired before the clock advanced")
	default:
	}

	f.Advance(120 * time.Second)
	select {
	case got := <-tk.C():
		if want := epoch.Add(120 * time.Second); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	default:
		t.Fatal("ticker did not fire after a full interval")
	}
}

// A ticker whose buffer is full must drop ticks rather than block, exactly as
// time.Ticker does. Blocking here would deadlock any test that advances the
// clock past several intervals without draining.
func TestFakeTickerDropsTicksWhenNotDrained(t *testing.T) {
	f := NewFake(epoch)
	tk := f.NewTicker(time.Minute)
	defer tk.Stop()

	f.Advance(10 * time.Minute) // ten intervals, one slot

	n := 0
	for {
		select {
		case <-tk.C():
			n++
			continue
		default:
		}
		break
	}
	if n != 1 {
		t.Fatalf("got %d buffered ticks, want 1 (the rest must be dropped)", n)
	}
}

func TestFakeTickerStopSilencesIt(t *testing.T) {
	f := NewFake(epoch)
	tk := f.NewTicker(time.Minute)
	tk.Stop()
	f.Advance(5 * time.Minute)
	select {
	case <-tk.C():
		t.Fatal("stopped ticker fired")
	default:
	}
}

func TestFakeAfterFiresOnlyOnce(t *testing.T) {
	f := NewFake(epoch)
	ch := f.After(30 * time.Second)

	f.Advance(10 * time.Second)
	select {
	case <-ch:
		t.Fatal("After fired before its deadline")
	default:
	}

	f.Advance(25 * time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("After did not fire past its deadline")
	}

	f.Advance(time.Hour)
	select {
	case <-ch:
		t.Fatal("After fired a second time")
	default:
	}
}

// System must satisfy Clock. A compile-time assertion is cheaper than
// discovering the mismatch when main.go is wired.
var _ Clock = System{}
var _ Clock = (*Fake)(nil)
