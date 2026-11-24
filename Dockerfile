# Builder and runtime share the Debian 13 (trixie) suite so glibc matches.
FROM rust:1.95-slim-trixie@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0 AS builder

# clang and libclang-dev for pg_query's bindgen step; build-essential for the C sources.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency layer: compile the crate graph against placeholder targets first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Make the real sources newer than the placeholder build so cargo rebuilds the crate.
RUN find src -type f -exec touch {} + \
    && cargo build --release --locked \
    && strip --strip-all target/release/postgres-mcp

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de

COPY --from=builder /build/target/release/postgres-mcp /usr/local/bin/postgres-mcp

USER nonroot:nonroot
ENV MCP_HOST=0.0.0.0 MCP_PORT=8432
EXPOSE 8432

# Probes GET /health on the container's own port.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/usr/local/bin/postgres-mcp", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/postgres-mcp"]
CMD ["http"]

LABEL org.opencontainers.image.title="postgres-mcp" \
      org.opencontainers.image.description="Read-only MCP server for PostgreSQL and TimescaleDB" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/matpb/postgres-mcp-rs"
