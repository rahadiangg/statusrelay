package main

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/config"
	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

var testEpoch = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

func fullConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Parse(strings.NewReader(`
sources:
  - id: huawei-intl
    kind: huawei
    regions: [{code: ap-southeast-4, name: AP-Jakarta}]
    services: [ecs]
  - id: huawei-nomirror
    kind: huawei
    all_regions: true
    mirror_url: none
    min_severity: major
notify:
  retry: {attempts: 2, backoff: 1s}
  telegram: [{name: tg, chat_id: "1", token_env: T}]
  smtp: [{name: mail, addr: "127.0.0.1:2525", from: a@example.com, to: [b@example.com], username: u, password_env: P}]
  webhook: [{name: hook, url: "https://example.com/h", secret_env: S, headers: {Authorization: "Bearer x"}}]
`), func(k string) string { return map[string]string{"T": "123:abc", "P": "pw", "S": "sec"}[k] })
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestBuildSources(t *testing.T) {
	cfg := fullConfig(t)
	srcs, err := buildSources(cfg, clock.NewFake(testEpoch), slog.Default(), "statwatch/test")
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	if len(srcs) != 2 || srcs[0].ID() != "huawei-intl" || srcs[0].Kind() != "huawei" || srcs[1].ID() != "huawei-nomirror" {
		t.Errorf("got %d sources: %v", len(srcs), srcs)
	}

	cfg.Sources[0].Kind = "aws"
	if _, err := buildSources(cfg, clock.NewFake(testEpoch), slog.Default(), "statwatch/test"); err == nil || !strings.Contains(err.Error(), "aws") {
		t.Errorf("unknown kind: got %v, want error naming aws", err)
	}
}

func TestBuildSinks(t *testing.T) {
	cfg := fullConfig(t)
	sinks, err := buildSinks(cfg, clock.NewFake(testEpoch), "statwatch/test")
	if err != nil {
		t.Fatalf("buildSinks: %v", err)
	}
	names := make([]string, len(sinks))
	for i, s := range sinks {
		names[i] = s.Name()
	}
	if got := strings.Join(names, ","); got != "telegram/tg,smtp/mail,webhook/hook" {
		t.Errorf("got %s", got)
	}

	cfg.Notify.LogOnly = true
	if sinks, err := buildSinks(cfg, clock.NewFake(testEpoch), "x"); err != nil || sinks != nil {
		t.Errorf("log_only: got %v, %v; want nil, nil", sinks, err)
	}

	cfg = fullConfig(t)
	cfg.Notify.Webhook[0].URL = "ftp://nope"
	if _, err := buildSinks(cfg, clock.NewFake(testEpoch), "x"); err == nil {
		t.Error("bad webhook url should fail sink construction")
	}
	cfg = fullConfig(t)
	cfg.Notify.SMTP[0].Addr = "no-port"
	if _, err := buildSinks(cfg, clock.NewFake(testEpoch), "x"); err == nil {
		t.Error("bad smtp addr should fail sink construction")
	}
}

func TestBuildFiltersAndOptions(t *testing.T) {
	cfg := fullConfig(t)
	f := buildFilters(cfg)
	if !f["huawei-intl"].Regions["ap-southeast-4"] || !f["huawei-intl"].Services["ECS"] || f["huawei-intl"].MinSeverity != incident.SeverityInfo {
		t.Errorf("filter wrong: %+v", f["huawei-intl"])
	}
	if len(f["huawei-nomirror"].Regions) != 0 || f["huawei-nomirror"].MinSeverity != incident.SeverityMajor {
		t.Errorf("filter wrong: %+v", f["huawei-nomirror"])
	}
	o := pollerOptions(cfg, clock.NewFake(testEpoch), slog.Default())
	if o.Interval != cfg.PollInterval || o.VanishGrace != cfg.VanishGrace || len(o.Filters) != 2 || o.Clock == nil {
		t.Errorf("options wrong: %+v", o)
	}
}

func TestRunExitCodes(t *testing.T) {
	if code := run([]string{"-version"}); code != 0 {
		t.Errorf("-version: got %d, want 0", code)
	}
	if code := run([]string{"-bogus"}); code != 2 {
		t.Errorf("bad flag: got %d, want 2", code)
	}
	if code := run([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}); code != 2 {
		t.Errorf("missing config: got %d, want 2", code)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("sources: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-config", bad}); code != 2 {
		t.Errorf("invalid config: got %d, want 2", code)
	}
}

func TestRunExitsWhenPortIsTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	body := "http: {listen: \"" + ln.Addr().String() + "\"}\nstate_file: " + filepath.Join(t.TempDir(), "s.json") +
		"\nsources: [{id: a, kind: huawei, all_regions: true, base_url: \"http://127.0.0.1:1/intl\", mirror_url: none}]\nnotify: {log_only: true}\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// The listener is bound before the poller starts, so this returns
	// without ever touching the (unreachable) source.
	if code := run([]string{"-config", cfg}); code != 2 {
		t.Errorf("port taken: got %d, want 2", code)
	}
}

func TestSourceIDsAndSinkNames(t *testing.T) {
	cfg := fullConfig(t)
	if got := strings.Join(sourceIDs(cfg), ","); got != "huawei-intl,huawei-nomirror" {
		t.Errorf("sourceIDs: %s", got)
	}
	sinks, _ := buildSinks(cfg, clock.NewFake(testEpoch), "x")
	if got := strings.Join(sinkNames(sinks), ","); got != "telegram/tg,smtp/mail,webhook/hook" {
		t.Errorf("sinkNames: %s", got)
	}
}
