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

# The user a parser pool's task processes run as (PLAN.md 2.17): not root, so a task process
# has no capabilities, which closes containment's gaps for raw sockets and for calls on other
# processes of the same user. It owns no files and has no shell or home.
RUN useradd --system --uid 10001 --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ace4-task

# py-spy for the Python pool's tests (PLAN.md 4.3), where the pool's image puts it, at the version
# and hashes of python/tool-requirements.txt; keep them in step. Only the binary comes out of the
# wheel, which pip isn't here to install.
RUN case "$(dpkg --print-architecture)" in \
        arm64) wheel=60/c3/c9384da6992d64e0dffab551cda3d1e990de1a2685fcfcc16fc8e5a98b18/py_spy-0.4.3-py2.py3-none-manylinux2014_aarch64.manylinux_2_17_aarch64.whl \
            sha256=bbcec46930d464b3bfc142d6d02ade4dd8ad5627823263b3eff0280e80c7c132 ;; \
        amd64) wheel=78/1f/651389a861f6148754443834a50dd576993257af5f645d4316ab94505267/py_spy-0.4.3-py2.py3-none-manylinux1_x86_64.manylinux_2_5_x86_64.whl \
            sha256=8a4277225f470d394a85cca0cdd944bef87f0097b6f20150a6dd3ac2e92806b8 ;; \
        *) echo "no py-spy for this architecture" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/py-spy.whl "https://files.pythonhosted.org/packages/$wheel" \
    && echo "$sha256  /tmp/py-spy.whl" | sha256sum -c - \
    && mkdir -p /opt/ace4/tools/bin \
    && python3 -c "import zipfile; open('/opt/ace4/tools/bin/py-spy', 'wb').write(zipfile.ZipFile('/tmp/py-spy.whl').read('py_spy-0.4.3.data/scripts/py-spy'))" \
    && chmod 755 /opt/ace4/tools/bin/py-spy \
    && rm /tmp/py-spy.whl
