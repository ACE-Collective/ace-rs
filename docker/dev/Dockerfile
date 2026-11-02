# The dev container: the pinned toolchain plus mold, sccache and bacon.
# The tag must match the channel in rust-toolchain.toml, so rustup never downloads another toolchain.
FROM rust:1.99.1-trixie

# clang drives the link so it can hand it to mold.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang mold \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt

# libmagic for ace-yara's mime types (PLAN.md 1.7), with its magic database pinned: the
# mime_type filter in YARA rules compares against libmagic's answer, so the database must not
# change under the rules. These are the versions and the database ace3's image has, so both
# answer alike. When Debian replaces 1:5.46-5 this build fails; change the versions and the
# hash together, on purpose.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        file=1:5.46-5 \
        libmagic-dev=1:5.46-5 \
        libmagic-mgc=1:5.46-5 \
        libmagic1t64=1:5.46-5 \
    && rm -rf /var/lib/apt/lists/* \
    && echo "23e4e113bd1e43940d079f9f8a9a105ce7b99321c917623808701eac99cb81af  /usr/lib/file/magic.mgc" \
        | sha256sum -c -

# Built from crates.io at fixed versions. --locked uses each tool's own lockfile.
RUN cargo install --locked sccache@0.18.0 bacon@3.26.0 \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# sqlx's CLI, at the version of the workspace's sqlx: `cargo sqlx migrate` and
# `cargo sqlx prepare`, which writes the offline query data in .sqlx/ (PLAN.md 2.2).
RUN cargo install --locked sqlx-cli@0.9.0 --no-default-features --features postgres,rustls,sqlx-toml \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# Link with mold. These are set here rather than in .cargo/config.toml so that builds outside
# this container, such as CI's, don't need mold.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=clang \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold"

# sccache caches compiled dependencies in a named volume (see compose.yaml).
ENV RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache \
    SCCACHE_CACHE_SIZE=10G

# The dev container's main process. See the script for why it exists.
COPY poll-host-changes /usr/local/bin/poll-host-changes
CMD ["poll-host-changes"]
