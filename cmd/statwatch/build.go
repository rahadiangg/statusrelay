package main

import (
	"fmt"
	"log/slog"

	"github.com/rahadiangg/statwatch/internal/config"
	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/alibaba"
	"github.com/rahadiangg/statwatch/internal/incident/huawei"
	"github.com/rahadiangg/statwatch/internal/notify"
	"github.com/rahadiangg/statwatch/internal/notify/smtp"
	"github.com/rahadiangg/statwatch/internal/notify/telegram"
	"github.com/rahadiangg/statwatch/internal/notify/webhook"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
	"github.com/rahadiangg/statwatch/internal/poller"
)

// buildSources wires config to adapters with an explicit switch on kind.
//
// No registry, no init(): a grep for "huawei" finds every place the adapter
// is referenced, and importing this package has no side effects.
func buildSources(cfg config.Config, clk clock.Clock, log *slog.Logger, ua string) ([]incident.Source, error) {
	out := make([]incident.Source, 0, len(cfg.Sources))
	for _, sc := range cfg.Sources {
		switch sc.Kind {
		case "huawei":
			opts := []huawei.Option{
				huawei.WithRegions(sc.RegionCodes(), sc.RegionNames()),
				huawei.WithPreferLang(sc.PreferLang),
				huawei.WithAllowNonIntl(sc.AllowNonIntl),
				huawei.WithLogger(log.With("source", sc.ID)),
				huawei.WithClock(clk),
				huawei.WithUserAgent(ua),
			}
			switch sc.MirrorURL {
			case "":
				opts = append(opts, huawei.WithMirror(huawei.DefaultMirrorURL))
			case "none":
				// No mirror: the operator has decided the fallback host is not
				// acceptable (for instance, a .cn egress policy).
			default:
				opts = append(opts, huawei.WithMirror(sc.MirrorURL))
			}
			s, err := huawei.New(sc.ID, sc.BaseURL, opts...)
			if err != nil {
				return nil, fmt.Errorf("source %s: %w", sc.ID, err)
			}
			out = append(out, s)
		case "alibaba":
			// No mirror option: config rejects mirror_url for this kind.
			s, err := alibaba.New(sc.ID, sc.BaseURL,
				alibaba.WithRegions(sc.RegionCodes(), sc.RegionNames()),
				alibaba.WithPreferLang(sc.PreferLang),
				alibaba.WithLogger(log.With("source", sc.ID)),
				alibaba.WithClock(clk),
				alibaba.WithUserAgent(ua),
			)
			if err != nil {
				return nil, fmt.Errorf("source %s: %w", sc.ID, err)
			}
			out = append(out, s)
		default:
			// Config validation already rejects this; the switch is still
			// exhaustive so a new kind in config without an adapter here is a
			// startup error, never a silently skipped source.
			return nil, fmt.Errorf("source %s: unknown kind %q", sc.ID, sc.Kind)
		}
	}
	return out, nil
}

// buildSinks constructs every configured transport, each wrapped in the
// shared retry policy. A constructor failure (bad address, bad URL) is fatal
// before the loop starts.
func buildSinks(cfg config.Config, clk clock.Clock, ua string) ([]poller.Sink, error) {
	if cfg.Notify.LogOnly {
		return nil, nil
	}
	n := cfg.Notify
	wrap := func(s notify.Notifier) poller.Sink {
		return notify.WithRetry(s, clk, n.Retry.Attempts, n.Retry.Backoff)
	}
	var out []poller.Sink
	for _, t := range n.Telegram {
		s, err := telegram.New(t.Name, t.Token, t.ChatID, telegram.WithThreadID(t.ThreadID), telegram.WithUserAgent(ua))
		if err != nil {
			return nil, err
		}
		out = append(out, wrap(s))
	}
	for _, m := range n.SMTP {
		opts := []smtp.Option{smtp.WithClock(clk), smtp.WithUserAgent(ua)}
		if m.Username != "" {
			opts = append(opts, smtp.WithAuth(m.Username, m.Password))
		}
		s, err := smtp.New(m.Name, m.Addr, m.From, m.To, opts...)
		if err != nil {
			return nil, err
		}
		out = append(out, wrap(s))
	}
	for _, w := range n.Webhook {
		opts := []webhook.Option{webhook.WithHeaders(w.Headers), webhook.WithUserAgent(ua), webhook.WithTimeout(cfg.FetchTimeout)}
		if w.Secret != "" {
			opts = append(opts, webhook.WithSecret(w.Secret))
		}
		s, err := webhook.New(w.Name, w.URL, opts...)
		if err != nil {
			return nil, err
		}
		out = append(out, wrap(s))
	}
	return out, nil
}

func buildFilters(cfg config.Config) map[string]incident.Filter {
	out := make(map[string]incident.Filter, len(cfg.Sources))
	for _, s := range cfg.Sources {
		out[s.ID] = s.Filter()
	}
	return out
}

func pollerOptions(cfg config.Config, clk clock.Clock, log *slog.Logger) poller.Options {
	return poller.Options{
		Interval:          cfg.PollInterval,
		FetchTimeout:      cfg.FetchTimeout,
		SelfCheckInterval: cfg.SelfCheckInterval,
		StaleAfter:        cfg.StaleAfter,
		VanishGrace:       cfg.VanishGrace,
		Filters:           buildFilters(cfg),
		Clock:             clk,
		Log:               log,
	}
}
