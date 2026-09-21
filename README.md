# statusrelay

Polls a cloud provider's public status page, diffs each observation against
persisted state, and delivers incident events — new, updated, resolved, and
its own *source blind / recovered* transitions — to Telegram, SMTP, or a
webhook. Exposes Prometheus metrics and liveness/readiness probes.

Today it supports one provider, Huawei Cloud (international site). Region
filtering is client-side by region **code** because the upstream silently
ignores its own `region_code` parameter.

> **"No incidents" is not "healthy."** The upstream has no status field; its
> green grid is a projection of published incidents. Alerting on
> `statusrelay_incidents_open == 0` as a health signal misreads the source.
> Alert on the events statusrelay emits, and on `statusrelay_source_blind`.

## Install

Release archives for linux, macOS and Windows (amd64, arm64) are on the
[releases page](https://github.com/rahadiangg/statusrelay/releases). Each
contains `statusrelay`, `statusrelayctl`, this README, the license and
`statusrelay.example.yaml`. `checksums.txt` is SHA-256.

```sh
# from source
go install github.com/rahadiangg/statusrelay/cmd/statusrelay@latest
go install github.com/rahadiangg/statusrelay/cmd/statusrelayctl@latest
```

macOS: the binaries are not notarized. If Gatekeeper refuses to run one:
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

Image: `ghcr.io/rahadiangg/statusrelay`, tags `vX.Y.Z`, `vX.Y`, `vX`, `latest`
(floating tags never point at a prerelease). Multi-arch linux/amd64 and
linux/arm64, distroless, runs as uid 65532, no shell. The config is read from
`$STATUSRELAY_CONFIG` (`/etc/statusrelay/statusrelay.yaml`) and state is written
to `/data`; mount a volume there or state is lost on restart and every open
incident is re-announced. Secrets come from the environment, never the file.

Liveness: `GET /healthz` (200, or 503 when the poll loop has stalled).
Readiness: `GET /readyz` (503 while any source is blind). Metrics:
`GET /metrics`. The image has no HEALTHCHECK; point your orchestrator's
probes at these.

## Configure

Copy [`statusrelay.example.yaml`](statusrelay.example.yaml) and edit. Every key
is validated at startup; unknown keys are an error. Then:

```sh
statusrelayctl check-config -config statusrelay.yaml
```

`check-config` runs the same loader as the daemon and prints the resolved
configuration with secrets redacted. **Give each region its `name` as well
as its `code`**: the pair is verified against the live catalogue at startup
and the daemon refuses to run on a mismatch. AP-Jakarta is `ap-southeast-4`;
`ap-southeast-3` is Singapore. A wrong code monitors the wrong country
forever and reports healthy.

First deploy: set `notify.log_only: true`, watch the logs for one poll
cycle, then switch it off. Cold start only reports what is currently open;
history is never alerted.

## Run

```sh
statusrelay -config statusrelay.yaml     # or $STATUSRELAY_CONFIG, or ./statusrelay.yaml
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
make test-live    # hits the REAL upstream; asserts the schema has not drifted
make snapshot     # full GoReleaser pipeline locally, nothing published
```

Releases are cut by pushing a semver tag (`v1.2.3`, or `v1.2.3-rc.1` for a
prerelease): CI runs the full suite, then GoReleaser publishes the archives
and the multi-arch image.

## License

MIT — see [LICENSE](LICENSE).
