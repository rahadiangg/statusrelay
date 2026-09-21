// Command statwatchctl is the operator's companion to statwatch.
//
// Today it validates a configuration file. Commands that need a running
// daemon (inspecting state, forcing a poll) arrive with the HTTP API.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rahadiangg/statwatch/internal/config"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: statwatchctl <command> [flags]")
	fmt.Fprintln(w, "  check-config [-config path]   load, resolve and validate a config file")
	fmt.Fprintln(w, "  version                       print version")
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "statwatchctl %s (%s)\n", version, commit)
		return 0
	case "check-config":
		return checkConfig(args[1:], stdout, stderr, getenv)
	default:
		fmt.Fprintf(stderr, "statwatchctl: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

// checkConfig prints the resolved configuration with secrets redacted. It
// runs the same Load as the daemon, so "check-config passes" means "the
// daemon will start", short of reaching the network.
func checkConfig(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config file (default $"+config.EnvConfig+" or ./statwatch.yaml)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := config.ConfigPath(*cfgPath, getenv)
	cfg, err := config.Load(path, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "%s: INVALID\n%v\n", path, err)
		return 1
	}

	fmt.Fprintf(stdout, "%s: OK\n", path)
	fmt.Fprintf(stdout, "poll every %s, fetch timeout %s, self-check every %s, blind after %s, vanish grace %d\n",
		cfg.PollInterval, cfg.FetchTimeout, cfg.SelfCheckInterval, cfg.StaleAfter, cfg.VanishGrace)
	fmt.Fprintf(stdout, "state file: %s\n", cfg.StateFile)
	if cfg.HTTP.Listen == "" {
		fmt.Fprintln(stdout, "http: DISABLED — no /metrics, /healthz, /readyz")
	} else {
		fmt.Fprintf(stdout, "http: %s (/metrics /healthz /readyz)\n", cfg.HTTP.Listen)
	}
	for _, s := range cfg.Sources {
		regions := "ALL regions"
		if !s.AllRegions {
			regions = fmt.Sprintf("%d region(s) %v", len(s.Regions), s.RegionCodes())
			if s.RegionNames() != nil {
				regions += fmt.Sprintf(" named %v (checked live at startup)", s.RegionNames())
			} else {
				regions += " (no names given: codes are NOT verified against the catalogue)"
			}
		}
		fmt.Fprintf(stdout, "source %s (%s): %s, min severity %s, services %v\n",
			s.ID, s.Kind, regions, s.Severity, s.Services)
	}
	if cfg.Notify.LogOnly {
		fmt.Fprintln(stdout, "notify: LOG ONLY — no alerts will be sent")
	}
	for _, t := range cfg.Notify.Telegram {
		fmt.Fprintf(stdout, "notify telegram/%s: chat %s, token from $%s (%d chars)\n", t.Name, t.ChatID, t.TokenEnv, len(t.Token))
	}
	for _, m := range cfg.Notify.SMTP {
		auth := "no auth"
		if m.Username != "" {
			auth = fmt.Sprintf("user %s, password from $%s", m.Username, m.PasswordEnv)
		}
		fmt.Fprintf(stdout, "notify smtp/%s: %s from %s to %v, %s\n", m.Name, m.Addr, m.From, m.To, auth)
	}
	for _, w := range cfg.Notify.Webhook {
		sig := "unsigned"
		if w.SecretEnv != "" {
			sig = "signed with $" + w.SecretEnv
		}
		fmt.Fprintf(stdout, "notify webhook/%s: %s, %s, %d header(s)\n", w.Name, w.URL, sig, len(w.Headers))
	}
	return 0
}
