# syntax=docker/dockerfile:1
#
# The images of ace4's Compose stack (PLAN.md 2.29): ace4-ace, the core; ace4-parsers, the
# parser pool; ace4-sandbox, the parser pool whose image carries the tools its modules run
# (PLAN.md 7.3); ace4-lookups, the network pool; and
# ace4-responder, the recorded-response server of the end-to-end test. One build stage compiles every binary once, and each image is a
# target of this file. The build's target directory is a BuildKit cache, so a rebuild compiles
# only what changed; it isn't the dev container's target/ volume.

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
# vendor/unautoit, which is ace3's third_party/unautoit, as ace3's Dockerfile builds it: libautoit's
# tests, then a static binary with Go 1.27.3, ace3's, so it's the same binary. It's GPL-3 and runs as
# a program of its own; its licence and those of the Go modules in it go beside it, as ace3's do.
# docker/dev/Dockerfile and docker/ace4/Dockerfile have this same stage.
FROM golang:1.27.3-trixie AS unautoit
ARG TARGETOS
ARG TARGETARCH
COPY vendor/unautoit /src/unautoit
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

FROM rust:1.99.1-trixie AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang mold \
    && rm -rf /var/lib/apt/lists/*
# libmagic at the dev image's pinned version (docker/dev/Dockerfile, PLAN.md 1.7)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        file=1:5.46-5 libmagic-dev=1:5.46-5 libmagic-mgc=1:5.46-5 libmagic1t64=1:5.46-5 \
    && rm -rf /var/lib/apt/lists/*

# libclang for the `opencv` crate's bindings, over the OpenCV stage above, linked statically
RUN apt-get update \
    && apt-get install -y --no-install-recommends libclang-dev=1:19.0-63 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=opencv /opt/opencv /opt/opencv
ENV LIBCLANG_PATH=/usr/lib/llvm-19/lib \
    OPENCV_INCLUDE_PATHS=/opt/opencv/include/opencv5 \
    OPENCV_LINK_PATHS=/opt/opencv/lib,/opt/opencv/lib/opencv5/3rdparty \
    OPENCV_LINK_LIBS=static=opencv_objdetect,static=opencv_photo,static=opencv_features,static=opencv_flann,static=opencv_imgcodecs,static=opencv_imgproc,static=opencv_geometry,static=opencv_core,static=liblibjpeg-turbo,static=liblibopenjp2,static=liblibpng,static=liblibtiff,static=liblibwebp,static=zlib,static=kleidicv_hal,static=kleidicv_thread,static=kleidicv,static=tegra_hal,static=ittnotify,stdc++

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=clang \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    SQLX_OFFLINE=true

WORKDIR /src
COPY . .
RUN --mount=type=cache,id=ace4-images-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=ace4-images-target,target=/src/target \
    cargo build --release --locked -p ace -p ace-testkit --bins \
    && mkdir -p /out \
    && cp target/release/ace target/release/ace-parsers target/release/ace-sandbox target/release/ace-lookups \
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
# the lease API for the pools, and the JSON API for people (crates/ace-app/src/serve.rs)
EXPOSE 8080 8000
CMD ["ace", "serve"]

# The parser pool. Its supervisor runs as root so it can start each task process as ace4-task,
# a user with no capabilities that owns no files (PLAN.md 2.17).
FROM runtime AS parsers
RUN useradd --system --uid 10001 --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ace4-task \
    && mkdir -p /var/lib/ace4/rulesets
COPY --from=build /out/ace-parsers /usr/local/bin/ace-parsers
CMD ["ace-parsers"]

# The sandbox pool (PLAN.md 7.3, 7.5 batch 10): a parser pool whose supervisor also runs, at a task's
# request, the tools its modules declare, each as a contained process of its own (ace_pool::tools).
# The tools are ace3's versions (docs/modules.md, *External tools*), from Debian trixie; unace is in
# non-free. ImageMagick's extra coders, the URW fonts, poppler's data and Archive::Zip are what ace3's
# image has for zbarimg, Ghostscript, pdftotext and ExifTool. Batch 11 adds the JVM with CFR 0.151,
# upx, unautoit, and .NET's 10.0.14 runtime with ilspycmd and de4dotEx (decision 18): the headless
# JRE, where ace3's default-jre adds the GUI libraries nothing here uses, and the runtime from
# Microsoft's repository, where ace3 installs the whole SDK. Batch 12 adds dmg2img and 7-Zip.
FROM runtime AS sandbox
ADD --checksum=sha256:d0c2f69250c6ce0d4c6220b142f999d039a3c560af7f980b943687d106ca8e38 \
    https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb /tmp/packages-microsoft-prod.deb
RUN sed -i -e '/^Components: main$/ s/$/ contrib non-free/' /etc/apt/sources.list.d/debian.sources \
    && dpkg -i /tmp/packages-microsoft-prod.deb && rm /tmp/packages-microsoft-prod.deb \
    && mkdir -p /usr/share/man/man1 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
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
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ace4-task
# Batch 12's macOS image tools, at ace3's versions: dmg2img, and 7-Zip, whose 7z loads its formats from
# 7z.so beside it and RAR's codecs from 7zip-rar's Codecs/Rar.so, in non-free, as ace3's does. A layer
# of their own, so the one above stays cached.
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
COPY --from=build /out/ace-sandbox /usr/local/bin/ace-sandbox
CMD ["ace-sandbox"]

# The network pool, which contains itself before it starts.
FROM runtime AS lookups
COPY --from=build /out/ace-lookups /usr/local/bin/ace-lookups
USER ace4
CMD ["ace-lookups"]

# The libraries tools/library-diff/run (PLAN.md 4.8) compares each Rust port with. Nothing in the
# stack runs this: the Python pool that did went at PLAN.md 4.13. Python is ace3's, 3.14 on trixie,
# so the libraries behave as they do there. The base is pinned by digest and every file pip installs
# by hash, so a build gets these bytes or fails. python/requirements.in says what's pinned and why,
# and tools/python/lock regenerates the hashes. The three GitHub archives need setuptools to build,
# so it's installed first, pinned. It stays, because XLMMacroDeobfuscator imports distutils, which
# Python 3.12 removed and setuptools now provides. wheel goes.
#
# Files in the tree that need these libraries, such as tools/oletools/make-tables, run on it as
# ace4-python-libraries:latest.
FROM python:3.14.10-slim-trixie@sha256:af8a5aa14780025dbfbcfbc81bd8a91ebd87711dd5b0f48ed71090949dd7cb1d AS python-libraries
# a Rust side of the diff runs here too, and ace-mod-xlm's links libmagic
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libmagic-mgc=1:5.46-5 libmagic1t64=1:5.46-5 \
    && rm -rf /var/lib/apt/lists/*
COPY python/build-requirements.txt python/requirements.txt /tmp/requirements/
RUN pip install --no-cache-dir --disable-pip-version-check --no-deps --require-hashes \
        -r /tmp/requirements/build-requirements.txt \
    && pip install --no-cache-dir --disable-pip-version-check --no-deps --require-hashes \
        --no-build-isolation -r /tmp/requirements/requirements.txt \
    && pip uninstall -y --disable-pip-version-check wheel packaging \
    && pip check --disable-pip-version-check \
    && python -c "import msoffcrypto, oletools.olevba, pcodedmp.pcodedmp, pyxlsb2, xlrd2, XLMMacroDeobfuscator.deobfuscator" \
    && rm -rf /tmp/requirements

# pikepdf and html2text for tools/library-diff/run (PLAN.md 4.9's and 4.11's comparisons), apart
# because decision 8 kept pikepdf out of the Python pool. Same Python, wheels only, by hash.
FROM python:3.14.10-slim-trixie@sha256:af8a5aa14780025dbfbcfbc81bd8a91ebd87711dd5b0f48ed71090949dd7cb1d AS pdf-libraries
COPY python/pdf-requirements.txt /tmp/pdf-requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check --no-deps --require-hashes \
        --only-binary :all: -r /tmp/pdf-requirements.txt \
    && pip check --disable-pip-version-check \
    && python -c "import pikepdf" \
    && rm /tmp/pdf-requirements.txt

# The end-to-end test's recorded RDAP and Splunk APIs (tools/ace3/dumps/reference).
FROM runtime AS responder
COPY --from=build /out/replay-server /usr/local/bin/replay-server
COPY tools/ace3/dumps/reference /recordings
COPY tools/ace3/trees/dns.json /recordings/trees.dns.json
USER ace4
CMD ["replay-server"]
