# The dev container: the pinned toolchain plus mold, sccache and bacon, and the sandbox pool's
# tools and OpenCV (PLAN.md 7.5 batches 10 and 11).

# OpenCV 5.0.0, the release ace3's opencv-python 5.0.0.93 is built from, for the ocr and qrcode
# modules' `opencv` crate (PLAN.md 7.3). It keeps the wheel's defaults, so the same code runs: its
# KleidiCV and carotene HALs on arm64 and pthreads for parallel_for. It differs where nothing here
# uses it: static libraries of only the modules the two modules call, built-in image libraries, and
# no OpenCL, GUI or video. docker/dev/Dockerfile and docker/ace4/Dockerfile have this same stage, so
# BuildKit builds it once.
FROM rust:1.99.1-trixie AS opencv
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake=3.31.6-2 ninja-build \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:b0528f5a1d379d59d4701cb28c36e22214cc51cf64594e5b56f2d3e6c0233095 \
    https://github.com/opencv/opencv/archive/refs/tags/5.0.0.tar.gz /tmp/opencv-5.0.0.tar.gz
RUN tar -xzf /tmp/opencv-5.0.0.tar.gz -C /tmp \
    && cmake -S /tmp/opencv-5.0.0 -B /tmp/opencv-build -G Ninja \
        -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/opt/opencv \
        -D BUILD_SHARED_LIBS=OFF \
        -D BUILD_LIST=core,imgproc,imgcodecs,photo,objdetect,features,flann,geometry \
        -D BUILD_TESTS=OFF -D BUILD_PERF_TESTS=OFF -D BUILD_EXAMPLES=OFF -D BUILD_DOCS=OFF \
        -D BUILD_opencv_apps=OFF -D BUILD_JAVA=OFF -D BUILD_opencv_python3=OFF \
        -D WITH_OPENCL=OFF -D WITH_FFMPEG=OFF -D WITH_GSTREAMER=OFF -D WITH_V4L=OFF \
        -D WITH_GTK=OFF -D WITH_QT=OFF -D WITH_AVIF=OFF -D WITH_OPENEXR=OFF -D WITH_JASPER=OFF \
        -D WITH_SPNG=OFF -D BUILD_ZLIB=ON -D BUILD_PNG=ON -D BUILD_JPEG=ON -D BUILD_TIFF=ON \
        -D BUILD_WEBP=ON -D BUILD_OPENJPEG=ON -D WITH_TBB=OFF -D WITH_OPENMP=OFF \
        -D WITH_PTHREADS_PF=ON -D WITH_LAPACK=OFF -D WITH_EIGEN=OFF \
    && cmake --build /tmp/opencv-build \
    && cmake --install /tmp/opencv-build \
    && cp /tmp/opencv-build/CMakeCache.txt /opt/opencv/CMakeCache.txt \
    && rm -rf /tmp/opencv-5.0.0.tar.gz /tmp/opencv-5.0.0 /tmp/opencv-build

# unautoit, the AutoIt extractor the autoit module runs (PLAN.md 7.5 batch 11), built from
# vendor/unautoit (compose.yaml gives this build the vendor directory), which is ace3's third_party/unautoit, as ace3's Dockerfile builds it: libautoit's
# tests, then a static binary with Go 1.27.3, ace3's, so it's the same binary. It's GPL-3 and runs as
# a program of its own; its licence and those of the Go modules in it go beside it, as ace3's do.
# docker/dev/Dockerfile and docker/ace4/Dockerfile have this same stage.
FROM golang:1.27.3-trixie AS unautoit
ARG TARGETOS
ARG TARGETARCH
COPY --from=vendor unautoit /src/unautoit
RUN cd /src/unautoit/third_party/libautoit && go test ./... \
    && cd /src/unautoit && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/unautoit . \
    && mkdir -p /out/doc/modules \
    && cp LICENSE /out/doc/LICENSE && cp "$(go env GOROOT)/LICENSE" /out/doc/LICENSE.go \
    && GOOS=$TARGETOS GOARCH=$TARGETARCH go list -deps \
        -f '{{with .Module}}{{if and (not .Main) (not .Replace)}}{{.Path}} {{.Dir}}{{end}}{{end}}' . | sort -u | \
    while read -r path dir; do \
        mkdir -p "/out/doc/modules/$path" && \
        find "$dir" -maxdepth 1 -type f \( -iname 'licen[cs]e*' -o -iname 'copying*' -o -iname 'notice*' \) \
            -exec cp {} "/out/doc/modules/$path/" \; && \
        [ -n "$(ls "/out/doc/modules/$path")" ] || { echo "no license file in Go module $path" >&2; exit 1; }; \
    done

# ilspycmd and de4dotEx, the .NET tools the ilspy and de4dot modules run (PLAN.md 7.5 batch 11,
# decision 18), as ace3's Dockerfile installs them: ilspycmd 11.0.0.9375 as a .NET tool, and de4dotEx
# 3.10.0 (commit 5ffdf0f0) published self-contained, on the .NET SDK 10.0.403, ace3's, which bundles
# the 10.0.14 runtime. The SDK stays in this stage: ilspycmd runs on the runtime alone.
# docker/dev/Dockerfile and docker/ace4/Dockerfile have this same stage.
FROM debian:13.7-slim AS dotnet-tools
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
ADD --checksum=sha256:d0c2f69250c6ce0d4c6220b142f999d039a3c560af7f980b943687d106ca8e38 \
    https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb /tmp/packages-microsoft-prod.deb
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && dpkg -i /tmp/packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends dotnet-sdk-10.0=10.0.403-1 \
        dotnet-runtime-10.0=10.0.14-1 dotnet-hostfxr-10.0=10.0.14-1 dotnet-host=10.0.14-1 \
        dotnet-runtime-deps-10.0=10.0.14-1 aspnetcore-runtime-10.0=10.0.14-1 \
        dotnet-targeting-pack-10.0=10.0.14-1 aspnetcore-targeting-pack-10.0=10.0.14-1 \
        dotnet-apphost-pack-10.0=10.0.14-1 \
    && rm -rf /var/lib/apt/lists/* /tmp/packages-microsoft-prod.deb
RUN dotnet tool install --tool-path /opt/dotnet ilspycmd --version 11.0.0.9375 \
    && git clone --branch 3.10.0 --depth 1 https://github.com/GDATAAdvancedAnalytics/de4dotEx.git /usr/src/de4dotEx \
    && test "$(git -C /usr/src/de4dotEx rev-parse HEAD)" = 5ffdf0f0da26034b9eb860f12ae26aab5968b0e2 \
    && dotnet publish /usr/src/de4dotEx/de4dot/de4dot.csproj -c Release -f net10.0 -o /opt/de4dotEx \
    && chmod +x /opt/de4dotEx/de4dot \
    && rm -rf /usr/src/de4dotEx /root/.nuget

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

# The sandbox pool's tools (PLAN.md 7.5 batches 10 to 12, docs/modules.md's *External tools*), at the
# versions docker/ace4/Dockerfile's sandbox image pins, which are ace3's, so the sandbox runner's
# tests and the modules' tests run the programs ace3 runs. unace is in non-free. strace is for
# finding what a tool opens. libclang is what the `opencv` crate generates its bindings with, over
# the OpenCV stage above (OPENCV_* below).
ADD --checksum=sha256:d0c2f69250c6ce0d4c6220b142f999d039a3c560af7f980b943687d106ca8e38 \
    https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb /tmp/packages-microsoft-prod.deb
RUN sed -i -e '/^Components: main$/ s/$/ contrib non-free/' /etc/apt/sources.list.d/debian.sources \
    && dpkg -i /tmp/packages-microsoft-prod.deb && rm /tmp/packages-microsoft-prod.deb \
    && mkdir -p /usr/share/man/man1 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libclang-dev=1:19.0-63 \
        strace \
        tesseract-ocr=5.5.0-1+b1 tesseract-ocr-eng=1:4.1.0-2 tesseract-ocr-osd=1:4.1.0-2 \
        libtesseract5=5.5.0-1+b1 libleptonica6=1.84.1-4 \
        zbar-tools=0.23.93-8 libzbar0t64=0.23.93-8 \
        libmagickcore-7.q16-10=8:7.1.1.43+dfsg1-1+deb13u14 \
        libmagickcore-7.q16-10-extra=8:7.1.1.43+dfsg1-1+deb13u14 \
        libmagickwand-7.q16-10=8:7.1.1.43+dfsg1-1+deb13u14 \
        libimage-exiftool-perl=13.25+dfsg-1 libarchive-zip-perl=1.68-1 \
        poppler-utils=25.03.0-5+deb13u4 libpoppler147=25.03.0-5+deb13u4 poppler-data=0.4.12-1 \
        ghostscript=10.05.1~dfsg-1+deb13u3 libgs10=10.05.1~dfsg-1+deb13u3 \
        libgs10-common=10.05.1~dfsg-1+deb13u3 fonts-urw-base35=20200910-8 \
        unace-nonfree=2.5-10 \
        hunspell-en-us=1:2020.12.07-4 \
        openjdk-21-jre-headless=21.0.13+9-1~deb13u2 \
        upx-ucl=4.2.4-1.1 \
        dotnet-runtime-10.0=10.0.14-1 dotnet-hostfxr-10.0=10.0.14-1 dotnet-host=10.0.14-1 \
        dotnet-runtime-deps-10.0=10.0.14-1 \
    && rm -rf /var/lib/apt/lists/*
# batch 12's, in a layer of their own as in the sandbox image
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dmg2img=1.6.7+git20201227.a3e4134-0.1 7zip=25.01+dfsg-1~deb13u2 7zip-rar=25.00+ds-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/*
# installed rather than added in place: ADD's --chmod would give the directory it makes the file's mode
# too, and the task's user couldn't reach the jar
ADD --checksum=sha256:316e9015b9af2953fcff4fe86bf3bba705f32e7cd25bd6e535c698de8a25e837 \
    https://github.com/leibnitz27/cfr/releases/download/0.151/cfr-0.151.jar /tmp/cfr-0.151.jar
RUN install -D -m 644 /tmp/cfr-0.151.jar /usr/local/share/java/cfr-0.151.jar && rm /tmp/cfr-0.151.jar
COPY --from=unautoit /out/unautoit /usr/local/bin/unautoit
COPY --from=unautoit /out/doc /usr/local/share/doc/unautoit
COPY --from=dotnet-tools /opt/dotnet /opt/dotnet
COPY --from=dotnet-tools /opt/de4dotEx /opt/de4dotEx
COPY --from=opencv /opt/opencv /opt/opencv
# The `opencv` crate links the static libraries above rather than probing pkg-config. It drops a
# leading `lib` from each name, so the image libraries, `liblibpng.a` and the like, keep one.
ENV LIBCLANG_PATH=/usr/lib/llvm-19/lib \
    OPENCV_INCLUDE_PATHS=/opt/opencv/include/opencv5 \
    OPENCV_LINK_PATHS=/opt/opencv/lib,/opt/opencv/lib/opencv5/3rdparty \
    OPENCV_LINK_LIBS=static=opencv_objdetect,static=opencv_photo,static=opencv_features,static=opencv_flann,static=opencv_imgcodecs,static=opencv_imgproc,static=opencv_geometry,static=opencv_core,static=liblibjpeg-turbo,static=liblibopenjp2,static=liblibpng,static=liblibtiff,static=liblibwebp,static=zlib,static=kleidicv_hal,static=kleidicv_thread,static=kleidicv,static=tegra_hal,static=ittnotify,stdc++
