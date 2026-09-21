package config

import (
	"fmt"
	"strings"
	"time"
)

// Environment variables. Overrides exist for the two settings an operator
// changes per deployment without editing the file; secrets are resolved
// through the *_env keys in the YAML rather than fixed names, so two Telegram
// sinks can carry two tokens.
const (
	EnvConfig       = "STATWATCH_CONFIG"
	EnvStateFile    = "STATWATCH_STATE_FILE"
	EnvPollInterval = "STATWATCH_POLL_INTERVAL"
)

// ConfigPath returns the config file location: the flag value when set, else
// $STATWATCH_CONFIG, else the default.
func ConfigPath(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := getenv(EnvConfig); v != "" {
		return v
	}
	return "statwatch.yaml"
}

// applyEnv resolves secrets and scalar overrides. Errors name the variable,
// never its value.
func applyEnv(c *Config, getenv func(string) string) error {
	if v := getenv(EnvStateFile); v != "" {
		c.StateFile = v
	}
	if v := getenv(EnvPollInterval); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%w: %s=%q: %v", ErrInvalid, EnvPollInterval, v, err)
		}
		c.PollInterval = d
	}

	secret := func(where, envName string) (string, error) {
		if envName == "" {
			return "", nil // validate reports the missing key
		}
		v := getenv(envName)
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%w: %s names environment variable %s, which is unset or empty", ErrInvalid, where, envName)
		}
		return v, nil
	}
	var err error
	for i := range c.Notify.Telegram {
		t := &c.Notify.Telegram[i]
		if t.Token, err = secret("notify.telegram."+t.Name+".token_env", t.TokenEnv); err != nil {
			return err
		}
	}
	for i := range c.Notify.SMTP {
		s := &c.Notify.SMTP[i]
		if s.Password, err = secret("notify.smtp."+s.Name+".password_env", s.PasswordEnv); err != nil {
			return err
		}
	}
	for i := range c.Notify.Webhook {
		w := &c.Notify.Webhook[i]
		if w.Secret, err = secret("notify.webhook."+w.Name+".secret_env", w.SecretEnv); err != nil {
			return err
		}
	}
	return nil
}
