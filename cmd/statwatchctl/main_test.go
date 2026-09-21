package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodYAML = `
sources:
  - id: huawei-intl
    kind: huawei
    regions: [{code: ap-southeast-4, name: AP-Jakarta}]
  - id: all
    kind: huawei
    all_regions: true
notify:
  telegram: [{name: tg, chat_id: "1", token_env: T}]
  smtp: [{name: mail, addr: "h:587", from: a@example.com, to: [b@example.com], username: u, password_env: P}]
  webhook: [{name: hook, url: "https://example.com/h", secret_env: S}]
`

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRun(t *testing.T) {
	secrets := map[string]string{"T": "123:abc-secret", "P": "hunter2", "S": "s3cret"}
	good := write(t, goodYAML)
	bad := write(t, "sources: []\n")

	for _, tc := range []struct {
		name     string
		args     []string
		env      map[string]string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{name: "no args", wantCode: 2, wantErr: "usage"},
		{name: "unknown command", args: []string{"frob"}, wantCode: 2, wantErr: `unknown command "frob"`},
		{name: "version", args: []string{"version"}, wantCode: 0, wantOut: "statwatchctl"},
		{name: "check ok", args: []string{"check-config", "-config", good}, env: secrets, wantCode: 0, wantOut: "OK"},
		{name: "check invalid", args: []string{"check-config", "-config", bad}, wantCode: 1, wantErr: "INVALID"},
		{name: "check missing secret", args: []string{"check-config", "-config", good}, env: map[string]string{"T": "x", "P": "y"}, wantCode: 1, wantErr: "S"},
		{name: "check via env path", args: []string{"check-config"}, env: map[string]string{"STATWATCH_CONFIG": good, "T": "t", "P": "p", "S": "s"}, wantCode: 0, wantOut: "OK"},
		{name: "check bad flag", args: []string{"check-config", "-nope"}, wantCode: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(tc.args, &out, &errb, env(tc.env))
			if code != tc.wantCode {
				t.Errorf("got code %d, want %d (stderr: %s)", code, tc.wantCode, errb.String())
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("stdout %q lacks %q", out.String(), tc.wantOut)
			}
			if tc.wantErr != "" && !strings.Contains(errb.String(), tc.wantErr) {
				t.Errorf("stderr %q lacks %q", errb.String(), tc.wantErr)
			}
			for _, secret := range secrets {
				if strings.Contains(out.String(), secret) || strings.Contains(errb.String(), secret) {
					t.Errorf("secret %q leaked into output", secret)
				}
			}
		})
	}
}

func TestCheckConfigDescribesEverything(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"check-config", "-config", write(t, goodYAML)}, &out, &errb,
		env(map[string]string{"T": "tok", "P": "pw", "S": "sec"}))
	if code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	for _, want := range []string{
		"huawei-intl", "[ap-southeast-4]", "named [AP-Jakarta] (checked live",
		"ALL regions",
		"telegram/tg: chat 1, token from $T (3 chars)",
		"smtp/mail: h:587", "password from $P",
		"webhook/hook: https://example.com/h, signed with $S",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	unnamed := write(t, "sources: [{id: a, kind: huawei, regions: [{code: x}]}]\nnotify: {log_only: true}\n")
	out.Reset()
	run([]string{"check-config", "-config", unnamed}, &out, &errb, env(nil))
	if !strings.Contains(out.String(), "NOT verified") || !strings.Contains(out.String(), "LOG ONLY") {
		t.Errorf("unnamed/log-only warnings missing:\n%s", out.String())
	}
}
