// Package httpapi is the daemon's HTTP surface: Prometheus metrics and the
// two probes an orchestrator needs.
//
// The probes answer different questions on purpose. /healthz asks "is the
// loop alive?" and a 503 means restart me. /readyz asks "can I currently see
// every provider?" and a 503 means do not trust my silence — but restarting
// would not help, because the cause is upstream. Folding the two together
// either restarts a healthy process into the same outage or hides blindness
// behind a green check.
//
// No authentication and no TLS: the surface carries no secrets and no
// incident text, only counts and timestamps. Bind it to loopback or put it
// behind whatever your network already trusts.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rahadiangg/statusrelay/internal/platform/clock"
	"github.com/rahadiangg/statusrelay/internal/poller"
)

// Thresholds tunes the probes.
type Thresholds struct {
	// LoopStale is how long the loop may go without starting a poll before
	// /healthz reports it dead. See LoopStaleFor.
	LoopStale time.Duration
	Clock     clock.Clock
}

// LoopStaleFor derives the liveness threshold from the loop's own bounds:
// two intervals of slack plus the longest a single poll can legitimately
// take when the self-check, the fetch and every sink each hit their timeout.
// A slow-but-alive loop must not be restarted into the same outage.
func LoopStaleFor(pollInterval, fetchTimeout time.Duration, sinks int) time.Duration {
	return 2*pollInterval + fetchTimeout*time.Duration(2+sinks)
}

// Server is one listener.
type Server struct {
	addr   string
	ln     net.Listener
	srv    *http.Server
	health func() poller.Health
	th     Thresholds
	log    *slog.Logger
}

// New builds a Server. health is read on every probe; reg is gathered on
// every scrape.
func New(addr string, reg prometheus.Gatherer, health func() poller.Health, th Thresholds, log *slog.Logger) *Server {
	if th.Clock == nil {
		th.Clock = clock.System{}
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Server{addr: addr, health: health, th: th, log: log}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// A single failing collector must not blank the whole page; the
		// rest of the series are still true.
		ErrorHandling: promhttp.ContinueOnError,
	}))
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return s
}

// Handler exposes the mux for tests.
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Listen binds the address. Separate from Serve so a bind failure is a
// synchronous startup error: the caller refuses to start rather than run a
// watcher nobody can scrape.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("httpapi: listen %s: %w", s.addr, err)
	}
	s.ln = ln
	s.log.Info("http listening", "addr", ln.Addr().String())
	return nil
}

// Addr is the bound address, valid after Listen.
func (s *Server) Addr() string {
	if s.ln == nil {
		return s.addr
	}
	return s.ln.Addr().String()
}

// Serve runs until ctx is done, then drains for up to five seconds.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- s.srv.Serve(s.ln) }()

	select {
	case err := <-errc:
		return fmt.Errorf("httpapi: serve: %w", err)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("httpapi: shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("httpapi: serve: %w", err)
	}
	return nil
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	h := s.health()
	// Sub, not a comparison of absolutes: a clock stepped backwards yields a
	// negative age, which reads as fresh rather than as a stall.
	age := s.th.Clock.Now().Sub(h.LastLoop)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if age > s.th.LoopStale {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "loop stalled for %s (threshold %s)\n", age.Round(time.Second), s.th.LoopStale)
		return
	}
	fmt.Fprintln(w, "ok")
}

// readiness is the /readyz body.
type readiness struct {
	Ready    bool              `json:"ready"`
	NotReady map[string]string `json:"not_ready,omitempty"`
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	h := s.health()
	out := readiness{Ready: true, NotReady: map[string]string{}}
	if h.Sources == nil {
		// The poller has not published yet. Config guarantees at least one
		// source, so an absent map is "not started", never "all clear".
		out.NotReady["*"] = "poller not started"
	}
	ids := make([]string, 0, len(h.Sources))
	for id := range h.Sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sh := h.Sources[id]
		switch {
		case sh.Blind:
			out.NotReady[id] = "blind since " + sh.LastComplete.UTC().Format(time.RFC3339)
		case !sh.EverComplete:
			out.NotReady[id] = "no complete snapshot yet"
		}
	}
	out.Ready = len(out.NotReady) == 0
	w.Header().Set("Content-Type", "application/json")
	if !out.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(out)
}
