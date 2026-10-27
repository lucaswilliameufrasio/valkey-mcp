FROM rust:1.94-bookworm AS api-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p valkey-mcp

FROM debian:bookworm-slim AS api
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home app
COPY --from=api-build /src/target/release/valkey-mcp /usr/local/bin/valkey-mcp
COPY deploy/wait-for-local-oidc.sh /usr/local/bin/wait-for-local-oidc
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/usr/local/bin/wait-for-local-oidc"]

FROM node:22-alpine AS admin-build
RUN corepack enable
WORKDIR /app
COPY apps/admin/package.json apps/admin/pnpm-lock.yaml apps/admin/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY apps/admin ./
RUN pnpm exec svelte-kit sync && pnpm build

FROM node:22-alpine AS admin
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
COPY --from=admin-build --chown=node:node /app/build ./build
COPY --from=admin-build --chown=node:node /app/node_modules ./node_modules
COPY --from=admin-build --chown=node:node /app/package.json ./package.json
USER node
EXPOSE 3000
CMD ["node", "build"]
