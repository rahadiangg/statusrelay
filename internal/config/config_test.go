package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

func goldenDoc(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture %s is empty; a test reading nothing passes vacuously", name)
	}
	return b
}

// env returns a getenv over a fixed map. The real environment is never read.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var fullEnv = map[string]string{"TG_TOKEN": "123:abc", "SMTP_PW": "hunter2", "HOOK_SECRET": "s3cret"}

func TestParseFull(t *testing.T) {
	cfg, err := Parse(strings.NewReader(string(goldenDoc(t, "full.yaml"))), env(fullEnv))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"poll_interval", cfg.PollInterval, 30 * time.Second},
		{"fetch_timeout", cfg.FetchTimeout, 20 * time.Second},
		{"self_check_interval", cfg.SelfCheckInterval, 2 * time.Hour},
		{"stale_after", cfg.StaleAfter, 10 * time.Minute},
		{"vanish_grace", cfg.VanishGrace, 5},
		{"state_file", cfg.StateFile, "/var/lib/statwatch/state.json"},
		{"dev_log", cfg.DevLog, true},
		{"sources len", len(cfg.Sources), 2},
		{"source id", cfg.Sources[0].ID, "huawei-intl"},
		{"services upper-cased and trimmed", cfg.Sources[0].Services, []string{"ECS", "IAM"}},
		{"severity resolved", cfg.Sources[0].Severity, incident.SeverityMajor},
		{"prefer_lang", cfg.Sources[0].PreferLang, "zh"},
		{"region codes", cfg.Sources[0].RegionCodes(), []string{"ap-southeast-4", "ap-southeast-3"}},
		{"region names", cfg.Sources[0].RegionNames(), []string{"AP-Jakarta", "AP-Singapore"}},
		{"all_regions codes nil", cfg.Sources[1].RegionCodes(), []string(nil)},
		{"all_regions names nil", cfg.Sources[1].RegionNames(), []string(nil)},
		{"all_regions defaults severity", cfg.Sources[1].Severity, incident.SeverityInfo},
		{"all_regions defaults lang", cfg.Sources[1].PreferLang, "en"},
		{"retry", cfg.Notify.Retry, Retry{Attempts: 5, Backoff: time.Second}},
		{"telegram token resolved", cfg.Notify.Telegram[0].Token, "123:abc"},
		{"telegram thread", cfg.Notify.Telegram[0].ThreadID, int64(42)},
		{"smtp password resolved", cfg.Notify.SMTP[0].Password, "hunter2"},
		{"webhook secret resolved", cfg.Notify.Webhook[0].Secret, "s3cret"},
		{"webhook headers", cfg.Notify.Webhook[0].Headers, map[string]string{"Authorization": "Bearer abc"}},
	} {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s: got %#v, want %#v", tc.name, tc.got, tc.want)
		}
	}

	f := cfg.Sources[0].Filter()
	if f.IncludeGlobal {
		t.Error("include_global: false not honoured")
	}
	if !f.Regions["ap-southeast-4"] || f.Regions["ap-southeast-5"] || !f.Services["ECS"] || f.MinSeverity != incident.SeverityMajor {
		t.Errorf("filter wrong: %+v", f)
	}
	g := cfg.Sources[1].Filter()
	if !g.IncludeGlobal || len(g.Regions) != 0 || len(g.Services) != 0 {
		t.Errorf("all_regions filter wrong: %+v", g)
	}
}

func TestParseMinimalAppliesDefaults(t *testing.T) {
	cfg, err := Parse(strings.NewReader(string(goldenDoc(t, "minimal.yaml"))), env(nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := defaults()
	if cfg.PollInterval != want.PollInterval || cfg.FetchTimeout != want.FetchTimeout ||
		cfg.SelfCheckInterval != want.SelfCheckInterval || cfg.StaleAfter != want.StaleAfter ||
		cfg.VanishGrace != want.VanishGrace || cfg.StateFile != want.StateFile ||
		cfg.Notify.Retry != want.Notify.Retry {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if !cfg.Notify.LogOnly {
		t.Error("log_only lost")
	}
	if cfg.Sources[0].RegionNames() != nil {
		t.Error("unnamed regions must yield nil names, not empty strings")
	}
	if cfg.HTTP.Listen != ":9101" {
		t.Errorf("http.listen default %q, want :9101", cfg.HTTP.Listen)
	}
}

func TestHTTPListenForms(t *testing.T) {
	for _, tc := range []struct{ name, listen string }{
		{"disabled", `""`}, {"port only", `":9101"`}, {"loopback", `"127.0.0.1:9101"`}, {"ipv6", `"[::1]:9101"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader("http: {listen: "+tc.listen+"}\n"+validSource+"notify: {log_only: true}"), env(nil)); err != nil {
				t.Errorf("listen %s rejected: %v", tc.listen, err)
			}
		})
	}
}

func TestParseEmptyDocument(t *testing.T) {
	_, err := Parse(strings.NewReader(""), env(nil))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "sources") {
		t.Errorf("got %v, want ErrInvalid mentioning sources", err)
	}
}

const validSource = `
sources:
  - id: huawei-intl
    kind: huawei
    regions: [{code: ap-southeast-4}]
`

func TestParseRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		env  map[string]string
		want string // substring of the error
	}{
		{name: "unknown top-level key", yaml: "pol_interval: 60s\n" + validSource + "notify: {log_only: true}", want: "pol_interval"},
		{name: "unknown nested key", yaml: strings.Replace(validSource, "regions", "regons", 1) + "notify: {log_only: true}", want: "regons"},
		{name: "bare number duration", yaml: "poll_interval: 60\n" + validSource + "notify: {log_only: true}", want: "unit"},
		{name: "poll below floor", yaml: "poll_interval: 5s\n" + validSource + "notify: {log_only: true}", want: "poll_interval"},
		{name: "fetch_timeout zero", yaml: "fetch_timeout: 0s\n" + validSource + "notify: {log_only: true}", want: "fetch_timeout"},
		{name: "stale_after below poll", yaml: "stale_after: 30s\n" + validSource + "notify: {log_only: true}", want: "stale_after"},
		{name: "self_check below poll", yaml: "self_check_interval: 30s\n" + validSource + "notify: {log_only: true}", want: "self_check_interval"},
		{name: "vanish_grace zero", yaml: "vanish_grace: 0\n" + validSource + "notify: {log_only: true}", want: "vanish_grace"},
		{name: "empty state_file", yaml: "state_file: ''\n" + validSource + "notify: {log_only: true}", want: "state_file"},
		{name: "no sources", yaml: "sources: []\nnotify: {log_only: true}", want: "at least one source"},
		{name: "missing id", yaml: "sources: [{kind: huawei, all_regions: true}]\nnotify: {log_only: true}", want: "id is required"},
		{name: "duplicate id", yaml: "sources:\n  - {id: a, kind: huawei, all_regions: true}\n  - {id: a, kind: huawei, all_regions: true}\nnotify: {log_only: true}", want: "duplicate id"},
		{name: "unknown kind", yaml: "sources: [{id: a, kind: aws, all_regions: true}]\nnotify: {log_only: true}", want: `unknown kind "aws"`},
		{name: "no regions and not all", yaml: "sources: [{id: a, kind: huawei}]\nnotify: {log_only: true}", want: "all_regions: true explicitly"},
		{name: "regions and all_regions", yaml: "sources: [{id: a, kind: huawei, all_regions: true, regions: [{code: x}]}]\nnotify: {log_only: true}", want: "choose one"},
		{name: "region without code", yaml: "sources: [{id: a, kind: huawei, regions: [{name: AP-Jakarta}]}]\nnotify: {log_only: true}", want: "code is required"},
		{name: "duplicate region", yaml: "sources: [{id: a, kind: huawei, regions: [{code: x}, {code: x}]}]\nnotify: {log_only: true}", want: "duplicate code"},
		{name: "half-named regions", yaml: "sources: [{id: a, kind: huawei, regions: [{code: x, name: X}, {code: y}]}]\nnotify: {log_only: true}", want: "every region has a name or none"},
		{name: "empty service", yaml: "sources: [{id: a, kind: huawei, all_regions: true, services: ['']}]\nnotify: {log_only: true}", want: "services[0]"},
		{name: "bad severity", yaml: "sources: [{id: a, kind: huawei, all_regions: true, min_severity: urgent}]\nnotify: {log_only: true}", want: "min_severity"},
		{name: "no transports and not log_only", yaml: validSource, want: "log_only"},
		{name: "retry attempts zero", yaml: validSource + "notify: {log_only: true, retry: {attempts: 0}}", want: "attempts"},
		{name: "retry backoff negative", yaml: validSource + "notify: {log_only: true, retry: {backoff: -1s}}", want: "backoff"},
		{name: "telegram literal token", yaml: validSource + "notify: {telegram: [{name: a, chat_id: '1', token: 'abc'}]}", want: "token_env"},
		{name: "smtp literal password", yaml: validSource + "notify: {smtp: [{name: a, addr: 'h:25', from: a@b.c, to: [x@y.z], username: u, password: p}]}", want: "password_env"},
		{name: "webhook literal secret", yaml: validSource + "notify: {webhook: [{name: a, url: 'https://x', secret: s}]}", want: "secret_env"},
		{name: "telegram env unset", yaml: validSource + "notify: {telegram: [{name: a, chat_id: '1', token_env: NOPE}]}", want: "NOPE"},
		{name: "telegram env empty", yaml: validSource + "notify: {telegram: [{name: a, chat_id: '1', token_env: EMPTY}]}", env: map[string]string{"EMPTY": "  "}, want: "EMPTY"},
		{name: "telegram missing chat", yaml: validSource + "notify: {telegram: [{name: a, token_env: T}]}", env: map[string]string{"T": "t"}, want: "chat_id"},
		{name: "telegram missing token_env", yaml: validSource + "notify: {telegram: [{name: a, chat_id: '1'}]}", want: "token_env is required"},
		{name: "transport without name", yaml: validSource + "notify: {webhook: [{url: 'https://x'}]}", want: "name is required"},
		{name: "duplicate name across types", yaml: validSource + "notify: {webhook: [{name: a, url: 'https://x'}], telegram: [{name: a, chat_id: '1', token_env: T}]}", env: map[string]string{"T": "t"}, want: "duplicate name"},
		{name: "smtp username without password", yaml: validSource + "notify: {smtp: [{name: a, addr: 'h:25', from: a@b.c, to: [x@y.z], username: u}]}", want: "set together"},
		{name: "smtp password without username", yaml: validSource + "notify: {smtp: [{name: a, addr: 'h:25', from: a@b.c, to: [x@y.z], password_env: P}]}", env: map[string]string{"P": "p"}, want: "set together"},
		{name: "smtp missing to", yaml: validSource + "notify: {smtp: [{name: a, addr: 'h:25', from: a@b.c}]}", want: "addr, from and to"},
		{name: "webhook missing url", yaml: validSource + "notify: {webhook: [{name: a}]}", want: "url is required"},
		{name: "http.listen without port", yaml: "http: {listen: localhost}\n" + validSource + "notify: {log_only: true}", want: "http.listen"},
		{name: "http.listen garbage", yaml: "http: {listen: 'a:b:c'}\n" + validSource + "notify: {log_only: true}", want: "http.listen"},
		{name: "env poll override unparsable", yaml: validSource + "notify: {log_only: true}", env: map[string]string{EnvPollInterval: "soon"}, want: EnvPollInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.yaml), env(tc.env))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got err %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestSecretValueNeverInError(t *testing.T) {
	// An unset variable is the only secret-related error; make sure that an
	// unrelated set variable's value cannot leak through a message.
	_, err := Parse(strings.NewReader(validSource+"notify: {telegram: [{name: a, chat_id: '1', token_env: NOPE}]}"),
		env(map[string]string{"OTHER": "leaky-value"}))
	if err == nil || strings.Contains(err.Error(), "leaky-value") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	cfg, err := Parse(strings.NewReader(validSource+"notify: {log_only: true}"),
		env(map[string]string{EnvStateFile: "/tmp/other.json", EnvPollInterval: "2m"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateFile != "/tmp/other.json" || cfg.PollInterval != 2*time.Minute {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLogOnlyWithTransportsIsAllowed(t *testing.T) {
	cfg, err := Parse(strings.NewReader(validSource+"notify: {log_only: true, webhook: [{name: a, url: 'https://x'}]}"), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Notify.LogOnly || len(cfg.Notify.Webhook) != 1 {
		t.Errorf("got %+v", cfg.Notify)
	}
}

func TestLoadResolvesRelativeStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte("state_file: rel/state.json\n"+validSource+"notify: {log_only: true}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.StateFile) || !strings.HasSuffix(cfg.StateFile, filepath.Join("rel", "state.json")) {
		t.Errorf("got %q, want absolute path ending in rel/state.json", cfg.StateFile)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml"), env(nil)); err == nil {
		t.Error("missing file should error")
	}
}

func TestConfigPath(t *testing.T) {
	for _, tc := range []struct{ name, flag, envv, want string }{
		{name: "flag wins", flag: "/a.yaml", envv: "/b.yaml", want: "/a.yaml"},
		{name: "env second", flag: "", envv: "/b.yaml", want: "/b.yaml"},
		{name: "default last", flag: "", envv: "", want: "statwatch.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ConfigPath(tc.flag, env(map[string]string{EnvConfig: tc.envv}))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
