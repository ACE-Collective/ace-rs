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
# image has for zbarimg, Ghostscript, pdftotext and ExifTool. The JVM and .NET wait for batch 11.
FROM runtime AS sandbox
RUN sed -i -e '/^Components: main$/ s/$/ contrib non-free/' /etc/apt/sources.list.d/debian.sources \
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
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ace4-task
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
