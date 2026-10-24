# SPDX-License-Identifier: AGPL-3.0-only
FROM node:24.16.0-bookworm-slim@sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203 AS console-build
WORKDIR /src
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
COPY web/console/package.json ./web/console/package.json
RUN npm install --global "$(node -p "require('./web/console/package.json').packageManager")"
RUN --mount=type=cache,id=scoplen-server-pnpm,target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile --store-dir=/pnpm/store \
       --fetch-timeout=120000 --fetch-retries=2
COPY web/console/ ./web/console/
RUN pnpm --dir web/console build

FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS server-build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       build-essential ca-certificates cmake git perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
WORKDIR /src
COPY rust-toolchain.toml ./
RUN rustup show active-toolchain
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
ARG TARGETARCH
RUN --mount=type=cache,id=scoplen-server-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=scoplen-server-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=scoplen-server-target-linux-${TARGETARCH},target=/src/target,sharing=locked \
    touch Cargo.toml Cargo.lock rust-toolchain.toml \
    && find crates -type f -exec touch {} + \
    && cargo build --locked --release \
       -p scoplen-server --bin spl-server -p scoplen-ctl --bin splctl \
    && install -d -m 0700 -o 65532 -g 65532 /container-data/spl \
    && install -D -m 0755 target/release/spl-server /out/spl-server \
    && install -D -m 0755 target/release/splctl /out/splctl

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
LABEL org.opencontainers.image.title="Scoplen server" \
      org.opencontainers.image.source="https://github.com/scoplen/server" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=server-build /out/spl-server /out/splctl /app/
COPY --from=console-build /src/web/console/dist/ /app/console/
COPY --from=server-build --chown=65532:65532 --chmod=0700 /container-data/ /var/lib/
COPY deploy/personal.toml /etc/scoplen/personal.toml
COPY LICENSE /app/LICENSE
ENV SPL_CONFIG=/etc/scoplen/personal.toml
WORKDIR /app
USER 65532:65532
EXPOSE 8443
STOPSIGNAL SIGINT
ENTRYPOINT ["/app/spl-server"]
