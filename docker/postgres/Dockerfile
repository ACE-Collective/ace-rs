# syntax=docker/dockerfile:1
#
# ace4's Postgres (PLAN.md 7.11): the stack's pinned Postgres with pgvector, which the search index's
# embeddings need. It's the same base image the stack ran before, so an existing data volume opens
# unchanged; the extension is three files beside the server's own. pgvector is built from its release
# tarball, pinned by hash, with the base image's compiler flags and no -march=native, so the image
# runs on any CPU of its architecture.
FROM postgres:18.6-alpine3.24

ADD --checksum=sha256:cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85 \
    https://github.com/pgvector/pgvector/archive/refs/tags/v0.8.7.tar.gz /tmp/pgvector-0.8.7.tar.gz
# with_llvm=no: the extension's JIT bitcode would need the clang the server was built with, and a
# distance function gains nothing from being inlined into a JIT-compiled expression here
RUN apk add --no-cache --virtual .pgvector-build build-base \
    && tar -xzf /tmp/pgvector-0.8.7.tar.gz -C /tmp \
    && make -C /tmp/pgvector-0.8.7 OPTFLAGS="" with_llvm=no \
    && make -C /tmp/pgvector-0.8.7 OPTFLAGS="" with_llvm=no install \
    && install -D -m 644 /tmp/pgvector-0.8.7/LICENSE /usr/local/share/doc/pgvector/LICENSE \
    && rm -rf /tmp/pgvector-0.8.7 /tmp/pgvector-0.8.7.tar.gz \
    && apk del .pgvector-build
