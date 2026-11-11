# syntax=docker/dockerfile:1.7
FROM buildpack-deps:trixie-curl AS litestream
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

FROM rust:1.96.0-trixie AS builder
WORKDIR /src
COPY . .
RUN \
  --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,target=/src/target \
  cargo build --release --locked && install -D target/release/mcp-duxca-com /out/mcp-duxca-com

FROM debian:trixie-slim
WORKDIR /app
# litestream（Go）の GCS 向け TLS と、アプリの reqwest（rustls-platform-verifier が OS の証明書ストアを読む）の両方が使う
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
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
CMD ["/app/run.bash"]
