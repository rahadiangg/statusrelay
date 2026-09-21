package poller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// recObserver records every hook call as one line.
type recObserver struct {
	mu    sync.Mutex
	calls []string
}

func (r *recObserver) add(s string) { r.mu.Lock(); r.calls = append(r.calls, s); r.mu.Unlock() }
func (r *recObserver) PollDone(src string, d time.Duration, failures int, err error) {
	r.add(fmt.Sprintf("poll:%s:%v:fail=%d:%v", src, d, failures, err != nil))
}
func (r *recObserver) SnapshotSeen(src string, s *incident.Snapshot) {
	r.add(fmt.Sprintf("snap:%s:complete=%v:warn=%d", src, s.Complete, len(s.Warnings)))
}
func (r *recObserver) EventsEmitted(src string, evs []incident.Event) {
	r.add(fmt.Sprintf("events:%s:%s", src, kinds(evs)))
}
func (r *recObserver) Delivered(sink string, err error) {
	r.add(fmt.Sprintf("deliver:%s:%v", sink, err != nil))
}
func (r *recObserver) StateApplied(src string, s State) {
	r.add(fmt.Sprintf("state:%s:open=%d:unknown=%d:resolved=%d:blind=%v:complete=%v",
		src, s.Open, s.Unknown, s.Records[incident.StatusResolved], s.Blind, !s.LastComplete.IsZero()))
}
func (r *recObserver) SelfChecked(src string, err error) {
	r.add(fmt.Sprintf("selfcheck:%s:%v", src, err != nil))
}
func (r *recObserver) Saved(err error) { r.add(fmt.Sprintf("saved:%v", err != nil)) }

func TestObserverSequence(t *testing.T) {
	h := newHarness()
	obs := &recObserver{}
	h.opts.Observer = obs
	h.sinkB.SendFunc = func(context.Context, incident.Event) error { return errors.New("down") }
	r := record("src", "13", "jkt")
	src := scripted("src", snap("src", []incident.Record{r}, nil), nil)
	p := h.started(t, src)
	p.pollAll(context.Background())
	h.tick(p)

	want := strings.Join([]string{
		"selfcheck:src:false",
		"poll:src:0s:fail=0:false",
		"snap:src:complete=true:warn=0",
		"events:src:new",
		"deliver:fake/a:false",
		"deliver:fake/b:true",
		"state:src:open=1:unknown=0:resolved=0:blind=false:complete=true",
		"saved:false",
		"poll:src:0s:fail=1:true",
	}, "\n")
	if got := strings.Join(obs.calls, "\n"); got != want {
		t.Errorf("observer sequence:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestObserverSeesUnknownAndBlind(t *testing.T) {
	h := newHarness()
	obs := &recObserver{}
	h.opts.Observer = obs
	h.opts.StaleAfter = 2 * time.Minute
	r := record("src", "13", "jkt")
	src := scripted("src",
		snap("src", []incident.Record{r}, nil),
		snap("src", nil, nil), // absent from a complete snapshot → unknown (grace 2)
		nil, nil,              // failures → blind at t+3
	)
	p := h.started(t, src)
	p.pollAll(context.Background())
	h.tick(p)
	h.tick(p)
	h.tick(p)
	joined := strings.Join(obs.calls, "\n")
	if !strings.Contains(joined, "state:src:open=0:unknown=1:resolved=0:blind=false:complete=true") {
		t.Errorf("unknown not counted:\n%s", joined)
	}
	if !strings.Contains(joined, "events:src:source_blind") {
		t.Errorf("blind event not observed:\n%s", joined)
	}
	if hh := p.Health(); !hh.Sources["src"].Blind || !hh.Sources["src"].EverComplete || hh.Sources["src"].Failures != 2 {
		t.Errorf("health %+v", hh.Sources["src"])
	}
}

func TestHealthLifecycle(t *testing.T) {
	h := newHarness()
	inc := snap("src", nil, nil)
	inc.Complete = false
	src := scripted("src", inc, snap("src", nil, nil))
	p := h.started(t, src)

	hh := p.Health()
	if !hh.LastLoop.Equal(testEpoch) || hh.Sources["src"].EverComplete || hh.Sources["src"].Blind {
		t.Errorf("before first poll: %+v", hh)
	}
	p.pollAll(context.Background())
	if hh := p.Health(); hh.Sources["src"].EverComplete {
		t.Error("incomplete snapshot must not set EverComplete")
	}
	h.tick(p)
	hh = p.Health()
	at := testEpoch.Add(time.Minute)
	if !hh.Sources["src"].EverComplete || !hh.LastLoop.Equal(at) || !hh.Sources["src"].LastComplete.Equal(at) {
		t.Errorf("after complete poll: %+v", hh)
	}
	// The copy must be detached from poller state.
	hh.Sources["src"] = SourceHealth{Blind: true}
	if p.Health().Sources["src"].Blind {
		t.Error("Health() returned a live reference")
	}
}

func TestHealthReadConcurrently(t *testing.T) {
	h := newHarness()
	p := h.started(t, scripted("src"))
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = p.Health()
			}
		}
	}()
	for range 50 {
		h.tick(p)
	}
	close(stop)
	wg.Wait()
}

func TestHealthPublishedBeforeStartupChecks(t *testing.T) {
	h := newHarness()
	src := scripted("src")
	var p *Poller
	var during Health
	src.SelfCheckFunc = func(context.Context) error {
		// Runs inside start(), before the first poll: the probe view must
		// already name the source and report it as not yet complete.
		during = p.Health()
		return nil
	}
	p = New([]incident.Source{src}, nil, h.store, h.opts)
	if p.Health().Sources != nil {
		t.Error("health published before start")
	}
	if err := p.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	sh, ok := during.Sources["src"]
	if !ok || sh.EverComplete || sh.Blind {
		t.Errorf("during startup checks: %+v", during)
	}
}

func TestNopObserverIsDefault(t *testing.T) {
	p := New(nil, nil, &fakeStore{}, Options{})
	if _, ok := p.o.Observer.(Nop); !ok {
		t.Errorf("got %T, want Nop", p.o.Observer)
	}
}
