# statusrelay

Watches cloud providers' public status pages and relays incident events to
the channels you already use. It polls each provider, diffs every
observation against persisted state, and delivers what changed — new,
updated, resolved — plus its own *source blind / recovered* transitions, so
you find out when the feed itself goes quiet.

Single static binary, no database, Prometheus metrics, liveness and
readiness probes.

> **"No incidents" is not "healthy."** These status pages have no status
> field; their green grids are projections of published incidents. Alerting
> on `statusrelay_incidents_open == 0` as a health signal misreads the
> source. Alert on the events statusrelay emits and on
> `statusrelay_source_blind`.

## Providers

| `kind` | Provider | Region code example | Notes |
|---|---|---|---|
| `huawei` | Huawei Cloud (international) | `ap-southeast-4` = AP-Jakarta | `ap-southeast-3` is Singapore. Mirror on the `.cn` edge is used on failure. |
| `alibaba` | Alibaba Cloud (international) | `ap-southeast-5` = Indonesia (Jakarta) | `ap-southeast-1` is Singapore, `ap-southeast-3` is Malaysia. |
| `tencent` | Tencent Cloud (international) | `ap-jakarta` | Unknown codes get an empty grid at HTTP 200 upstream; statusrelay catches this at startup. |

Region filtering is client-side by region **code** — every one of these
APIs silently ignores or misroutes its own region parameter. Give each
region its `name` as well as its `code`: the pair is verified against the
live catalogue at startup and the daemon refuses to run on a mismatch. A
wrong code monitors the wrong country forever and reports healthy.

## Channels

| `notify.*` | Delivery | Secret |
|---|---|---|
| `telegram` | Bot API `sendMessage`, plain text, optional forum `thread_id` | bot token via `token_env` |
| `smtp` | One mail per event, STARTTLS when offered, optional auth | password via `password_env` |
| `webhook` | `POST` JSON (schema below), optional HMAC-SHA256 signature and static headers | signing secret via `secret_env` |

Several of each may be configured. Deliveries retry with exponential
backoff (`notify.retry`); a `429` `Retry-After` overrides the backoff.
`notify.log_only: true` logs every event instead of sending — use it on
first deploy.

### Routing

Each sink takes three optional keys. Absent means no restriction, so a
config with none routes everything everywhere.

```yaml
telegram:
  - name: oncall
    chat_id: "-100…"
    token_env: STATUSRELAY_TELEGRAM_TOKEN
    min_severity: major                  # info | minor | major | critical
    kinds: [new, resolved, source_blind] # exact, lower-case
    sources: [huawei-intl]               # source ids
```

Unknown severities always pass a floor. An explicitly empty list is a
config error, and **every source must have at least one sink that accepts
its `source_blind` event** or statusrelay refuses to start — a feed that
dies unnoticed is the failure this tool exists to catch. Events a sink's
route skips count as `deliveries_total{result="skipped"}`; an event no
sink accepts counts in `events_undelivered_total`.

### Message format

```
Subject: [statusrelay] NEW major · Huawei Cloud · AP-Jakarta (IAM, ECS)

NEW · major · Huawei Cloud (huawei-intl #13)
<provider title>
Details: https://status.service.huaweicloud.com/intl/
Status: open
Published: 2026-07-26 02:05 WIB
Watched: AP-Jakarta (IAM, ECS)
All regions: AP-Jakarta (IAM, ECS); AP-Singapore (IAM, ECS)

Update 2026-07-26 02:05 WIB:
  <only the new progress entries, never the full history>
```

The subject names the transition, the provider and *your* regions (capped
at three), never the provider's title. `Watched:` appears only when it is
narrower than `All regions:`. Timestamps use `notify.timezone` (IANA name,
default `UTC`); `sources[].display_name` overrides the per-kind default
(`Huawei Cloud`, `Alibaba Cloud`, `Tencent Cloud`). `Details:` links the
provider's own bulletin where one exists (Alibaba); Huawei and Tencent have
no per-incident page, so it links to their status dashboards.

### Webhook payload

Headers: `X-Statusrelay-Event-Id`, `X-Statusrelay-Event-Kind`, and, when a
`secret_env` is set, `X-Statusrelay-Signature: sha256=<hex HMAC of the body>`.
Redirects are refused; give the final URL.

```json
{
  "schema": 1,
  "event_id": "…", "thread_id": "…", "kind": "new", "cold_start": false,
  "source_id": "huawei-intl", "provider_id": "…",
  "title": "…", "title_lang": "en",
  "severity": "major", "raw_severity": "…", "status": "open",
  "started_at": "2026-09-21T07:00:00Z", "updated_at": null, "ended_at": null,
  "global": false,
  "url": "https://status.service.huaweicloud.com/intl/",
  "scope": [{"region_code": "ap-southeast-4", "region_name": "AP-Jakarta",
             "services": [{"abbr": "ECS", "name": "Elastic Cloud Server"}]}],
  "new_updates": [{"at": "2026-09-21T07:05:00Z", "text": "…", "lang": "en"}],
  "added": [], "removed": []
}
```

`kind` is one of `new`, `updated`, `minor_updated`, `scope_changed`,
`resolved`, `resolved_inferred`, `reopened`, `missed_and_resolved`,
`updated_after_resolve`, `vanished`, `scope_exited`, `source_blind`,
`source_recovered`. `thread_id` is stable across an incident's lifetime, so
a receiver can group its events.

## Install

Release archives for Linux, macOS and Windows (amd64, arm64) are on the
[releases page](https://github.com/rahadiangg/statusrelay/releases). Each
holds `statusrelay`, `statusrelayctl`, this README, the license and
`statusrelay.example.yaml`; `checksums.txt` is SHA-256.

```sh
# from source
go install github.com/rahadiangg/statusrelay/cmd/statusrelay@latest
go install github.com/rahadiangg/statusrelay/cmd/statusrelayctl@latest
```

macOS: the binaries are not notarized. If Gatekeeper refuses one:
`xattr -d com.apple.quarantine ./statusrelay`.

### Container

```sh
docker run --rm \
  -v "$PWD/statusrelay.yaml:/etc/statusrelay/statusrelay.yaml:ro" \
  -v statusrelay-data:/data \
  -e STATUSRELAY_TELEGRAM_TOKEN \
  -p 9101:9101 \
  ghcr.io/rahadiangg/statusrelay:latest
```

Image `ghcr.io/rahadiangg/statusrelay`, tags `vX.Y.Z`, `vX.Y`, `vX`,
`latest` (floating tags never point at a prerelease). linux/amd64 and
linux/arm64, distroless, uid 65532, no shell. Config is read from
`$STATUSRELAY_CONFIG` (`/etc/statusrelay/statusrelay.yaml`); state is
written under `/data` — mount a volume there or every open incident is
re-announced on restart. Secrets come from the environment, never the file.

There is no `HEALTHCHECK`; point your orchestrator at `GET /healthz`
(liveness: 503 when the poll loop has stalled) and `GET /readyz`
(readiness: 503 while any source is blind). Metrics: `GET /metrics`.

Metrics worth alerting on, all prefixed `statusrelay_`: `source_blind`,
`time() - last_complete_snapshot_timestamp_seconds`,
`events_undelivered_total`, `time() - last_delivery_success_timestamp_seconds`
(a dead sink before an incident), `delivery_retries_total` (a flapping
relay), `source_using_mirror`, and
`time() - oldest_open_incident_started_timestamp_seconds`. `events_total`
carries `kind` and `severity`; `deliveries_total` carries `ok`, `error` or
`skipped`; `delivery_duration_seconds` is a histogram per sink.

## Configure

Copy [`statusrelay.example.yaml`](statusrelay.example.yaml) — every key is
documented inline — and validate it:

```sh
statusrelayctl check-config -config statusrelay.yaml
```

`check-config` runs the same loader as the daemon and prints the resolved
configuration with secrets redacted, so "check-config passes" means "the
daemon will start", short of reaching the network. Unknown or misspelt
keys are errors, not silently ignored lines.

The minimum:

```yaml
sources:
  - id: huawei-intl
    kind: huawei
    regions:
      - {code: ap-southeast-4, name: AP-Jakarta}
notify:
  telegram:
    - name: oncall
      chat_id: "-1001234567890"
      token_env: STATUSRELAY_TELEGRAM_TOKEN
```

Per source: `regions` (or `all_regions: true`), optional `services`
allow-list, `include_global` (events the provider publishes with no
region), `min_severity` (`info` | `minor` | `major` | `critical`; unknown
severities always alert). Globals: `poll_interval` (floor 10s),
`stale_after` (no complete snapshot for this long ⇒ *source blind*),
`vanish_grace`, `state_file`, `http.listen`.

Environment overrides: `STATUSRELAY_CONFIG`, `STATUSRELAY_STATE_FILE`,
`STATUSRELAY_POLL_INTERVAL`.

First deploy: set `notify.log_only: true`, watch one poll cycle, then
switch it off. Cold start only reports what is currently open; history is
never alerted. The example file ends with a recipe for forcing one test
delivery.

## Run

```sh
statusrelay -config statusrelay.yaml   # or $STATUSRELAY_CONFIG, or ./statusrelay.yaml
statusrelay -version
```

Stops cleanly on SIGINT/SIGTERM. State is written atomically after every
poll. A corrupt state file is moved aside and the daemon cold-starts rather
than refusing to run during the outage it exists to report.

## Develop

```sh
make build        # both binaries, pure Go
make test         # vet + hermetic suite, -race
make lint         # golangci-lint v2
make test-live    # hits the REAL upstreams; asserts their schemas have not drifted
make snapshot     # full GoReleaser pipeline locally, nothing published
```

Releases are cut by pushing a semver tag (`v1.2.3`, or `v1.2.3-rc.1` for a
prerelease): CI runs the full suite, then GoReleaser publishes the archives
and the multi-arch image. A nightly workflow runs the live schema canary
and opens an issue when an upstream changes shape.

## License

MIT — see [LICENSE](LICENSE).
