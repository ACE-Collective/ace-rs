# syntax=docker/dockerfile:1
#
# The images of ace4's Compose stack (PLAN.md 2.29): ace4-ace, the core; ace4-parsers, the
# parser pool; ace4-lookups, the network pool; and ace4-responder, the recorded-response server
# of the end-to-end test. One build stage compiles every binary once, and each image is a
# target of this file. The build's target directory is a BuildKit cache, so a rebuild compiles
# only what changed; it isn't the dev container's target/ volume.

FROM rust:1.99.1-trixie AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang mold \
    && rm -rf /var/lib/apt/lists/*
# libmagic at the dev image's pinned version (docker/dev/Dockerfile, PLAN.md 1.7)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        file=1:5.46-5 libmagic-dev=1:5.46-5 libmagic-mgc=1:5.46-5 libmagic1t64=1:5.46-5 \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=clang \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    SQLX_OFFLINE=true

WORKDIR /src
COPY . .
RUN --mount=type=cache,id=ace4-images-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=ace4-images-target,target=/src/target \
    cargo build --release --locked -p ace -p ace-pools -p ace-testkit --bins \
    && mkdir -p /out \
    && cp target/release/ace target/release/ace-parsers target/release/ace-lookups \
        target/release/replay-server /out/

# What every image runs on: Debian with the pinned libmagic and its database, which the core's
# mime types and the YARA module's mime_type filter read.
FROM debian:13.7-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libmagic-mgc=1:5.46-5 libmagic1t64=1:5.46-5 \
    && rm -rf /var/lib/apt/lists/* \
    && echo "23e4e113bd1e43940d079f9f8a9a105ce7b99321c917623808701eac99cb81af  /usr/lib/file/magic.mgc" \
        | sha256sum -c -
RUN useradd --system --uid 10000 --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ace4

# The core: `ace serve`. git reads the signatures repository for ruleset builds, and curl is
# the healthcheck's.
FROM runtime AS ace
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ace /usr/local/bin/ace
USER ace4
EXPOSE 8080
CMD ["ace", "serve"]

# The parser pool. Its supervisor runs as root so it can start each task process as ace4-task,
# a user with no capabilities that owns no files (PLAN.md 2.17).
FROM runtime AS parsers
RUN useradd --system --uid 10001 --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ace4-task \
    && mkdir -p /var/lib/ace4/rulesets
COPY --from=build /out/ace-parsers /usr/local/bin/ace-parsers
CMD ["ace-parsers"]

# The network pool, which contains itself before it starts.
FROM runtime AS lookups
COPY --from=build /out/ace-lookups /usr/local/bin/ace-lookups
USER ace4
CMD ["ace-lookups"]

# The end-to-end test's recorded RDAP and Splunk APIs (tools/ace3/dumps/reference).
FROM runtime AS responder
COPY --from=build /out/replay-server /usr/local/bin/replay-server
COPY tools/ace3/dumps/reference /recordings
USER ace4
CMD ["replay-server"]
