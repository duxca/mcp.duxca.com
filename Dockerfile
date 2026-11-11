# syntax=docker/dockerfile:1.7
# ベースイメージは digest（マルチアーキの index）で固定する。上げるときはタグと digest を一緒に変える
FROM buildpack-deps:trixie-curl@sha256:9e486725325568707dbd794ca9b53cffb7ddee2b8ac1b94941ca4d3d8c6e9df9 AS litestream
ARG LITESTREAM_VERSION=v0.5.17
ARG LITESTREAM_TARBALL=litestream-0.5.17-linux-x86_64.tar.gz
# 値は https://github.com/benbjohnson/litestream/releases/download/${LITESTREAM_VERSION}/checksums.txt から取る
ARG LITESTREAM_SHA256=cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d
RUN set -eu; \
  curl -fsSL --proto '=https' -o /tmp/litestream.tar.gz \
    "https://github.com/benbjohnson/litestream/releases/download/${LITESTREAM_VERSION}/${LITESTREAM_TARBALL}"; \
  echo "${LITESTREAM_SHA256}  /tmp/litestream.tar.gz" | sha256sum -c -; \
  tar -xzf /tmp/litestream.tar.gz -C /usr/local/bin litestream; \
  /usr/local/bin/litestream version | grep -qxF -e "${LITESTREAM_VERSION}" -e "${LITESTREAM_VERSION#v}"

FROM scratch AS litestream-bin
COPY --from=litestream /usr/local/bin/litestream /litestream

FROM rust:1.96.0-trixie@sha256:58fe97504a0e4cbba5d85599619a589923d3e779472a6fb0840d58d1c4ba99d7 AS builder
WORKDIR /src
COPY . .
RUN \
  --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,target=/src/target \
  cargo build --release --locked && install -D target/release/mcp-duxca-com /out/mcp-duxca-com

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
WORKDIR /app
# litestream（Go）の GCS 向け TLS と、アプリの reqwest（rustls-platform-verifier が OS の証明書ストアを読む）の両方が使う
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
# root では動かさない。/app は DB の復元・WAL・litestream の作業ディレクトリに使うので書けるようにし、
# 実行ファイルと設定は root の持ち物のまま（書き換えられない）にする
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --home-dir /app --no-create-home --shell /usr/sbin/nologin app \
 && chown 10001:10001 /app
COPY --from=litestream /usr/local/bin/litestream /app/litestream
COPY db/litestream.yml /app/litestream.yml
COPY cli/run.bash /app/run.bash
COPY --from=builder /out/mcp-duxca-com /app/mcp-duxca-com
ENV BIND_ADDR=0.0.0.0 \
    PORT=8080 \
    PUBLIC_URL=https://mcp.duxca.com \
    DATABASE_PATH=/app/mcp.db \
    SQLITE_WAL_AUTOCHECKPOINT=0 \
    RUST_LOG=info
EXPOSE 8080
USER 10001:10001
CMD ["/app/run.bash"]
