// Package config loads the daemon's YAML configuration.
//
// It is hand-rolled on purpose: one struct, one decoder with KnownFields, one
// Validate. A typo in a key is a startup error, not a silently ignored line —
// on this tool the difference between ap-southeast-3 and ap-southeast-4 is
// which country you are monitoring, and a config layer that quietly drops what
// it does not recognise is how that goes unnoticed for a year.
//
// Secrets are never written in the file. Each secret key names an environment
// variable (token_env, password_env, secret_env) and the value is read at load,
// so the file is safe to commit and the process environment is the only place
// a credential lives.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// Config is the fully resolved, validated configuration.
type Config struct {
	PollInterval      time.Duration `yaml:"poll_interval"`
	FetchTimeout      time.Duration `yaml:"fetch_timeout"`
	SelfCheckInterval time.Duration `yaml:"self_check_interval"`
	StaleAfter        time.Duration `yaml:"stale_after"`
	VanishGrace       int           `yaml:"vanish_grace"`
	StateFile         string        `yaml:"state_file"`
	DevLog            bool          `yaml:"dev_log"`

	Sources []Source `yaml:"sources"`
	Notify  Notify   `yaml:"notify"`
	HTTP    HTTP     `yaml:"http"`
}

// HTTP configures the metrics/probe listener.
type HTTP struct {
	// Listen is host:port. Empty disables the listener entirely.
	Listen string `yaml:"listen"`
}

// Source is one status feed instance.
type Source struct {
	ID            string   `yaml:"id"`
	Kind          string   `yaml:"kind"`
	BaseURL       string   `yaml:"base_url"`
	MirrorURL     string   `yaml:"mirror_url"`
	AllRegions    bool     `yaml:"all_regions"`
	Regions       []Region `yaml:"regions"`
	Services      []string `yaml:"services"`
	IncludeGlobal *bool    `yaml:"include_global"` // pointer: absent means true
	MinSeverity   string   `yaml:"min_severity"`
	PreferLang    string   `yaml:"prefer_lang"`
	AllowNonIntl  bool     `yaml:"allow_non_intl"`

	// Resolved by Validate.
	Severity incident.Severity `yaml:"-"`
}

// Region is one watched region. Name is optional; when every region has one,
// the names are reconciled against the live catalogue at startup, which is
// the guard against watching the wrong country.
type Region struct {
	Code string `yaml:"code"`
	Name string `yaml:"name"`
}

// Notify holds every configured transport.
type Notify struct {
	LogOnly  bool       `yaml:"log_only"`
	Retry    Retry      `yaml:"retry"`
	Telegram []Telegram `yaml:"telegram"`
	SMTP     []SMTP     `yaml:"smtp"`
	Webhook  []Webhook  `yaml:"webhook"`
}

// Retry is the shared per-sink retry policy.
type Retry struct {
	Attempts int           `yaml:"attempts"`
	Backoff  time.Duration `yaml:"backoff"`
}

// Telegram is one bot/chat pair.
type Telegram struct {
	Name     string `yaml:"name"`
	ChatID   string `yaml:"chat_id"`
	TokenEnv string `yaml:"token_env"`
	ThreadID int64  `yaml:"thread_id"`

	Token string `yaml:"-"` // resolved from TokenEnv
}

// SMTP is one relay/recipient list.
type SMTP struct {
	Name        string   `yaml:"name"`
	Addr        string   `yaml:"addr"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
	Username    string   `yaml:"username"`
	PasswordEnv string   `yaml:"password_env"`

	Password string `yaml:"-"` // resolved from PasswordEnv
}

// Webhook is one JSON receiver.
type Webhook struct {
	Name      string            `yaml:"name"`
	URL       string            `yaml:"url"`
	SecretEnv string            `yaml:"secret_env"`
	Headers   map[string]string `yaml:"headers"`

	Secret string `yaml:"-"` // resolved from SecretEnv
}

// Defaults applied before the file is decoded, so an absent key means this
// rather than zero.
func defaults() Config {
	return Config{
		PollInterval:      60 * time.Second,
		FetchTimeout:      45 * time.Second,
		SelfCheckInterval: time.Hour,
		StaleAfter:        15 * time.Minute,
		VanishGrace:       3,
		StateFile:         "statwatch-state.json",
		Notify:            Notify{Retry: Retry{Attempts: 3, Backoff: 2 * time.Second}},
		HTTP:              HTTP{Listen: ":9101"},
	}
}

// Load reads path, applies environment overrides and validates. getenv is
// os.Getenv in the binaries and a map lookup in tests.
func Load(path string, getenv func(string) string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()
	cfg, err := Parse(f, getenv)
	if err != nil {
		return Config{}, err
	}
	// Relative paths are resolved against the cwd now so every later log
	// line names one unambiguous file.
	if !filepath.IsAbs(cfg.StateFile) {
		abs, err := filepath.Abs(cfg.StateFile)
		if err != nil {
			return Config{}, fmt.Errorf("%w: state_file: %v", ErrInvalid, err)
		}
		cfg.StateFile = abs
	}
	return cfg, nil
}

// Parse is Load without the filesystem: r is the YAML, getenv resolves
// secrets and overrides. Tests pass a map lookup and never touch the real
// environment.
func Parse(r io.Reader, getenv func(string) string) (Config, error) {
	cfg := defaults()
	dec := yaml.NewDecoder(r)
	// KnownFields turns a misspelt key into an error. A silently ignored
	// `regons:` would watch nothing and report nothing.
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, friendlyYAMLError(err))
	}
	if err := applyEnv(&cfg, getenv); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// friendlyYAMLError rewrites the two yaml.v3 messages operators hit most into
// actionable ones.
func friendlyYAMLError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "field token not found"),
		strings.Contains(msg, "field password not found"),
		strings.Contains(msg, "field secret not found"):
		return msg + " (secrets are not read from the file; use token_env / password_env / secret_env naming an environment variable)"
	case strings.Contains(msg, "into time.Duration"):
		return msg + " (durations need a unit, e.g. 60s or 15m)"
	}
	return msg
}

func (c *Config) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.PollInterval < 10*time.Second {
		bad("poll_interval %s is below the 10s floor; polling faster invites a WAF block", c.PollInterval)
	}
	if c.FetchTimeout <= 0 {
		bad("fetch_timeout must be positive")
	}
	if c.SelfCheckInterval < c.PollInterval {
		bad("self_check_interval %s is shorter than poll_interval %s", c.SelfCheckInterval, c.PollInterval)
	}
	if c.StaleAfter < c.PollInterval {
		bad("stale_after %s is shorter than poll_interval %s; the source would flap blind every poll", c.StaleAfter, c.PollInterval)
	}
	if c.VanishGrace < 1 {
		bad("vanish_grace must be at least 1")
	}
	if strings.TrimSpace(c.StateFile) == "" {
		bad("state_file must not be empty")
	}

	if len(c.Sources) == 0 {
		bad("sources: at least one source is required")
	}
	ids := map[string]bool{}
	for i := range c.Sources {
		s := &c.Sources[i]
		where := fmt.Sprintf("sources[%d]", i)
		if s.ID != "" {
			where = "sources." + s.ID
		}
		if s.ID == "" {
			bad("%s: id is required", where)
		} else if ids[s.ID] {
			bad("%s: duplicate id", where)
		}
		ids[s.ID] = true
		switch s.Kind {
		case "huawei":
		case "alibaba":
			// Rejected rather than ignored: an operator who sets mirror_url
			// believes failover exists, and a silently accepted key is how
			// that belief survives until the day it matters.
			if s.MirrorURL != "" {
				bad("%s: mirror_url is not supported for kind alibaba (one host, no mirror)", where)
			}
			if s.AllowNonIntl {
				bad("%s: allow_non_intl is meaningless for kind alibaba (one backend serves both sites)", where)
			}
		default:
			bad("%s: unknown kind %q (supported: huawei, alibaba)", where, s.Kind)
		}
		if err := s.validateRegions(); err != nil {
			bad("%s: %v", where, err)
		}
		for j, sv := range s.Services {
			if strings.TrimSpace(sv) == "" {
				bad("%s: services[%d] is empty", where, j)
			}
			s.Services[j] = strings.ToUpper(strings.TrimSpace(sv))
		}
		if s.MinSeverity == "" {
			s.MinSeverity = "info"
		}
		sev, ok := incident.ParseSeverity(s.MinSeverity)
		if !ok {
			bad("%s: min_severity %q is not one of info, minor, major, critical", where, s.MinSeverity)
		}
		s.Severity = sev
		if s.PreferLang == "" {
			s.PreferLang = "en"
		}
	}

	if err := c.Notify.validate(); err != nil {
		errs = append(errs, err)
	}
	if c.HTTP.Listen != "" {
		if _, _, err := net.SplitHostPort(c.HTTP.Listen); err != nil {
			bad("http.listen %q must be host:port (use \"\" to disable): %v", c.HTTP.Listen, err)
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(errs...))
}

// validateRegions enforces that "watch everything" is a deliberate choice.
// An empty list defaulting to all regions is how people end up believing they
// filtered when they did not.
func (s *Source) validateRegions() error {
	switch {
	case s.AllRegions && len(s.Regions) > 0:
		return errors.New("all_regions is true but regions are also listed; choose one")
	case !s.AllRegions && len(s.Regions) == 0:
		return errors.New("regions is empty; list the region codes to watch, or set all_regions: true explicitly")
	}
	seen := map[string]bool{}
	named := 0
	for i, r := range s.Regions {
		if strings.TrimSpace(r.Code) == "" {
			return fmt.Errorf("regions[%d]: code is required", i)
		}
		if seen[r.Code] {
			return fmt.Errorf("regions[%d]: duplicate code %q", i, r.Code)
		}
		seen[r.Code] = true
		if r.Name != "" {
			named++
		}
	}
	if named != 0 && named != len(s.Regions) {
		// ReconcileRegions requires equal-length lists, and a half-named list
		// would silently skip the name check for the unnamed half.
		return errors.New("regions: either every region has a name or none does")
	}
	return nil
}

// RegionCodes returns the codes in config order. Nil when watching all.
func (s Source) RegionCodes() []string {
	if s.AllRegions {
		return nil
	}
	out := make([]string, len(s.Regions))
	for i, r := range s.Regions {
		out[i] = r.Code
	}
	return out
}

// RegionNames returns the names when every region has one, else nil.
func (s Source) RegionNames() []string {
	if s.AllRegions || len(s.Regions) == 0 || s.Regions[0].Name == "" {
		return nil
	}
	out := make([]string, len(s.Regions))
	for i, r := range s.Regions {
		out[i] = r.Name
	}
	return out
}

// Filter builds the notification filter for this source.
func (s Source) Filter() incident.Filter {
	f := incident.Filter{
		Regions:       map[string]bool{},
		Services:      map[string]bool{},
		IncludeGlobal: s.IncludeGlobal == nil || *s.IncludeGlobal,
		MinSeverity:   s.Severity,
	}
	for _, c := range s.RegionCodes() {
		f.Regions[c] = true
	}
	for _, sv := range s.Services {
		f.Services[sv] = true
	}
	return f
}

func (n *Notify) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if n.Retry.Attempts < 1 {
		bad("notify.retry.attempts must be at least 1")
	}
	if n.Retry.Backoff < 0 {
		bad("notify.retry.backoff must not be negative")
	}
	total := len(n.Telegram) + len(n.SMTP) + len(n.Webhook)
	if total == 0 && !n.LogOnly {
		bad("notify: no transports configured; add telegram/smtp/webhook or set notify.log_only: true to run without alerts")
	}

	names := map[string]bool{}
	name := func(kind, nm string) {
		if strings.TrimSpace(nm) == "" {
			bad("notify.%s: name is required", kind)
			return
		}
		if names[nm] {
			bad("notify.%s.%s: duplicate name (names are shared across transport types)", kind, nm)
		}
		names[nm] = true
	}
	for _, t := range n.Telegram {
		name("telegram", t.Name)
		if strings.TrimSpace(t.ChatID) == "" {
			bad("notify.telegram.%s: chat_id is required", t.Name)
		}
		if t.TokenEnv == "" {
			bad("notify.telegram.%s: token_env is required", t.Name)
		}
	}
	for _, s := range n.SMTP {
		name("smtp", s.Name)
		if s.Addr == "" || s.From == "" || len(s.To) == 0 {
			bad("notify.smtp.%s: addr, from and to are required", s.Name)
		}
		if (s.Username == "") != (s.PasswordEnv == "") {
			bad("notify.smtp.%s: username and password_env must be set together", s.Name)
		}
	}
	for _, w := range n.Webhook {
		name("webhook", w.Name)
		if w.URL == "" {
			bad("notify.webhook.%s: url is required", w.Name)
		}
	}
	return errors.Join(errs...)
}
