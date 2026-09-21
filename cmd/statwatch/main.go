// Command statwatch polls status-page providers, diffs each observation
// against persisted state, and delivers the resulting incident events — and
// its own blind/recovered transitions — to the configured notifiers.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rahadiangg/statwatch/internal/config"
	"github.com/rahadiangg/statwatch/internal/httpapi"
	"github.com/rahadiangg/statwatch/internal/metrics"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
	"github.com/rahadiangg/statwatch/internal/platform/logging"
	"github.com/rahadiangg/statwatch/internal/poller"
	"github.com/rahadiangg/statwatch/internal/store"
)

// Set by -ldflags at build time; see the Makefile.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is main without os.Exit, so it can be exercised from a test.
func run(args []string) int {
	fs := flag.NewFlagSet("statwatch", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file (default $"+config.EnvConfig+" or ./statwatch.yaml)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("statwatch %s (%s)\n", version, commit)
		return 0
	}

	path := config.ConfigPath(*cfgPath, os.Getenv)
	cfg, err := config.Load(path, os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statwatch: %v\n", err)
		return 2
	}

	log := logging.New(cfg.DevLog)
	clk := clock.System{}
	ua := "statwatch/" + version

	sources, err := buildSources(cfg, clk, log)
	if err != nil {
		log.Error("building sources", "err", err)
		return 2
	}
	sinks, err := buildSinks(cfg, clk, ua)
	if err != nil {
		log.Error("building notifiers", "err", err)
		return 2
	}
	if cfg.Notify.LogOnly {
		log.Warn("notify.log_only is set: events are logged, nobody is paged")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	rec := metrics.New(reg, version, commit)
	rec.Init(sourceIDs(cfg), sinkNames(sinks))
	opts := pollerOptions(cfg, clk, log)
	opts.Observer = rec
	p := poller.New(sources, sinks, store.New(cfg.StateFile, clk), opts)

	// The listener binds before the loop starts, so a port clash is a
	// startup failure rather than a watcher that runs unscraped.
	httpErr := make(chan error, 1)
	if cfg.HTTP.Listen == "" {
		log.Warn("http.listen is empty: no /metrics, /healthz or /readyz")
	} else {
		th := httpapi.Thresholds{LoopStale: httpapi.LoopStaleFor(cfg.PollInterval, cfg.FetchTimeout, len(sinks)), Clock: clk}
		srv := httpapi.New(cfg.HTTP.Listen, reg, p.Health, th, log)
		if err := srv.Listen(); err != nil {
			log.Error("http", "err", err)
			return 2
		}
		go func() { httpErr <- srv.Serve(ctx) }()
	}

	log.Info("starting", "version", version, "config", path, "state_file", cfg.StateFile,
		"sources", len(sources), "sinks", len(sinks), "poll_interval", cfg.PollInterval, "http", cfg.HTTP.Listen)
	code := 0
	if err := p.Run(ctx); err != nil {
		log.Error("fatal", "err", err)
		code = 1
	}
	stop()
	if cfg.HTTP.Listen != "" {
		if err := <-httpErr; err != nil {
			log.Error("http", "err", err)
		}
	}
	log.Info("stopped")
	return code
}

func sourceIDs(cfg config.Config) []string {
	out := make([]string, len(cfg.Sources))
	for i, s := range cfg.Sources {
		out[i] = s.ID
	}
	return out
}

func sinkNames(sinks []poller.Sink) []string {
	out := make([]string, len(sinks))
	for i, s := range sinks {
		out[i] = s.Name()
	}
	return out
}
