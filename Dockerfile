# Built by GoReleaser (dockers_v2): the context holds prebuilt binaries laid
# out as <os>/<arch>/<binary>, so there is no compile step and no RUN on the
# target platform. That is what lets one buildx invocation produce linux/arm64
# on an amd64 runner without QEMU.

# The state directory has to exist and be writable by the non-root user, and
# distroless has no shell to mkdir with. This stage runs on the BUILD platform
# only to produce an empty, correctly-owned directory to copy across.
FROM --platform=$BUILDPLATFORM busybox:stable AS mk
RUN mkdir -p /data

# static: no libc, ships CA certificates (upstream is HTTPS) and tzdata.
# nonroot: uid 65532, no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETOS
ARG TARGETARCH

COPY --from=mk --chown=65532:65532 /data /data
COPY ${TARGETOS}/${TARGETARCH}/statwatch ${TARGETOS}/${TARGETARCH}/statwatchctl /usr/local/bin/

# Relative state_file resolves against the working directory, so WORKDIR and
# STATWATCH_STATE_FILE agree even if an operator's config omits state_file.
ENV STATWATCH_CONFIG=/etc/statwatch/statwatch.yaml \
    STATWATCH_STATE_FILE=/data/statwatch-state.json
WORKDIR /data
VOLUME /data
EXPOSE 9101

ENTRYPOINT ["/usr/local/bin/statwatch"]
