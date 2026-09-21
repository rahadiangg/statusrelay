# CLAUDE.md

## Working Rules

1. **Always write/update/fix unit tests** when there are code changes.
2. **Think forward and backward** — proposed solutions must be future-proof and backward-compatible.
3. **Check all edge cases** when thinking or proposing a solution.

## Commands

| Command | What it does |
|---|---|
| `make build` | Both binaries. Pure Go — no Node, no codegen. |
| `make test` | `go vet` + the full hermetic suite (`-race -count=1`). No network. |
| `make test-live` | Hits the REAL upstream; asserts the schema has not drifted. Never part of `make test`. |
| `make cover-check` | Coverage gate (85%). |
| `make lint` | golangci-lint v2. |

## Architecture

`cmd/statwatch` polls one or more status-page providers, diffs each observation
against persisted state, and fans the resulting events out to sinks (Prometheus
metrics, notifiers).

- `internal/incident` — **the contract package.** Source, Snapshot, Record, Filter,
  Fingerprint, and the pure Diff/Apply state machine. Imports nothing of ours;
  everything else imports it. Nothing outside it may depend on a concrete adapter.
- `internal/incident/huawei` — the Huawei SHD adapter.
- `internal/incident/alibaba` — the Alibaba Cloud Health Status adapter. Its own
  traps: errors arrive as HTTP 200 with `success:false`; a bogus `regionId`
  returns empty days at success; the catalogue endpoint needs a `Referer`;
  Jakarta is `ap-southeast-5` there (`-1` Singapore, `-3` Kuala Lumpur).
- `internal/incident/tencent` — the Tencent Cloud Health Dashboard adapter. Same
  disease: HTTP 200 + empty for unknown regions/codes; errors arrive as a 200
  with a `Response.Error` object; `BelongSite` is ignored; timestamps are UTC
  without a zone marker.
- `internal/incident/httpx` — hardened HTTP shared by adapters.
- `internal/incident/canary` — `//go:build live` schema-drift suite.
- `internal/poller` — the loop, failure accounting, and the sink bus.
- `internal/store` — persistence. `internal/notify` — transports.
- `internal/metrics` — Prometheus registry. `internal/httpapi` — /metrics, /healthz, /readyz.

Providers are wired by an explicit `buildSources()` in `cmd/statwatch`, not an
`init()` registry: greppable, no import side effects.

## The traps this codebase exists to survive

The upstream returns **HTTP 200 with an empty array for five distinct failure
conditions**, including "you called a renamed endpoint" and "you are reading a
different site's data". Three of them never surface an error anywhere:

1. **AP-Jakarta is `ap-southeast-4`.** `ap-southeast-3` is AP-Singapore. A wrong
   code monitors the wrong country forever and reports healthy.
2. **Dropping the `/intl` path prefix** serves the China-mainland dataset at 200.
3. **`?region_code=` is silently ignored** — filtering must be client-side.

Consequences encoded in the code, not in convention:
`Snapshot.Complete` (absence proves nothing when false) · `StatusUnknown` (a
record that vanished from both lists is **not** resolved) · a failed fetch
returns *before* the resolution sweep · `Record.Global` (a region-less event is a
real shape, not a parse failure) · `SeverityUnknown` always alerts.

**"No incidents" is not "healthy."** The services catalogue has no status field;
the upstream's own green grid is a client-side projection of published incidents.
Alerting on `statwatch_incidents_open == 0` as a health signal misreads the data
source, and that is the most likely way this tool causes harm.

## Code Standards

- `cmd/<binary>` + `internal/<domain>`. No `pkg/`.
- Config is hand-rolled: `Load() (Config, error)` plus small env helpers. No
  viper/koanf/envconfig. YAML file layer via `yaml.v3` with `KnownFields(true)`.
- `log/slog` only.
- Errors wrapped with `%w`; sentinels in the package's `errors.go`; `errors.Is`.
- Every package carries a `// Package x ...` doc comment; every `cmd` main opens
  with `// Command x ...`.
- **Comments explain the why and the failure mode prevented**, not the what.

## Testing

- Stdlib `testing` only. **No testify, no gomock.**
- Table-driven: struct slice inlined in the `range`, then `t.Run(tc.name, ...)`.
- Failures phrased `got X, want Y`. Use `t.Setenv`, `t.TempDir()`, `t.Helper()`.
- Hand-written fakes with `XxxFunc` fields, in `mock.go` inside the defining package.
- Golden files in `testdata/`, loaded via a `goldenDoc(t, name)` helper.
- Time is injected via `internal/platform/clock`. **No `time.Sleep` in any
  non-live test.**
- Always `-race -count=1`.
