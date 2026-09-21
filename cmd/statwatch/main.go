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

	"github.com/rahadiangg/statwatch/internal/config"
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

	log.Info("starting", "version", version, "config", path, "state_file", cfg.StateFile,
		"sources", len(sources), "sinks", len(sinks), "poll_interval", cfg.PollInterval)
	p := poller.New(sources, sinks, store.New(cfg.StateFile, clk), pollerOptions(cfg, clk, log))
	if err := p.Run(ctx); err != nil {
		log.Error("fatal", "err", err)
		return 1
	}
	log.Info("stopped")
	return 0
}
