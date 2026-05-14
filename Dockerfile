FROM --platform=$BUILDPLATFORM debian:trixie-slim AS builder-tools

ARG RUST_NIGHTLY_VERSION=nightly-2026-05-01
ARG ZIG_VERSION=0.15.2

ENV CARGO_HOME=/cargo \
    RUSTUP_HOME=/rustup \
    PATH="/cargo/bin:/rustup/toolchains/${RUST_NIGHTLY_VERSION}/bin:/zig:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config ca-certificates curl xz-utils build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain ${RUST_NIGHTLY_VERSION} \
    && curl -L https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz | tar -xJ && mv zig-x86_64-linux-${ZIG_VERSION} /zig \
    && cargo install --locked cargo-zigbuild --version 0.22.3 \
    && cargo install --locked cargo-chef --version 0.1.77 \
    && rustup target add \
        x86_64-unknown-linux-gnu \
        aarch64-unknown-linux-gnu

WORKDIR /app

## Cargo chef planner ##
FROM builder-tools AS planner

# prepare the recipe
COPY node ./node
COPY shared ./shared
COPY central ./central
COPY Cargo.toml ./
RUN cargo chef prepare --recipe-path recipe.json

## Builder base ##
FROM builder-tools AS builder-base
COPY --from=planner /app/recipe.json recipe.json

## glibc builder ##
FROM builder-base AS builder-glibc
ARG TARGETARCH

# map arch to target
RUN case "$TARGETARCH" in \
    amd64) echo "x86_64-unknown-linux-gnu" > /target.txt ;; \
    arm64) echo "aarch64-unknown-linux-gnu" > /target.txt ;; \
    *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac

# build dependencies
RUN cargo chef cook --release --zigbuild --target $(cat /target.txt) --recipe-path recipe.json

# build the project
COPY node ./node
COPY shared ./shared
COPY central ./central
COPY Cargo.toml ./
RUN cargo zigbuild --release --target $(cat /target.txt)

## debian runtime ##
FROM debian:trixie-slim AS runtime-debian
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder-glibc /app/target/*/release/argon-server /argon-server
COPY --from=builder-glibc /app/target/*/release/argon-node /argon-node

EXPOSE 4340/tcp

ENV INSIDE_DOCKER=1
ENTRYPOINT ["/argon-server"]
