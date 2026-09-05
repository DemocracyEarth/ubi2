FROM node:22-bookworm-slim@sha256:4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96 AS builder

ARG POH_SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
RUN test "$(printf '%s' "$POH_SOURCE_REVISION" | wc -c)" -eq 40 \
  && printf '%s' "$POH_SOURCE_REVISION" | grep -Eq '^[0-9a-f]{40}$' \
  && printf '%s' "$SOURCE_DATE_EPOCH" | grep -Eq '^[0-9]{9,}$'

ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm:$PATH
ENV NEXT_TELEMETRY_DISABLED=1
ENV POH_BUILD_STANDALONE_API=true
ENV NEXT_PUBLIC_SELF_ENDPOINT=https://proofofhumanity.org/api/self-verify
ENV NEXT_PUBLIC_SELF_ENV=staging
ENV NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL=https://sepolia.base.org

RUN corepack enable && corepack prepare pnpm@10.2.1 --activate

WORKDIR /repo
COPY .pnpmfile.cjs package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/proofofhumanity/package.json apps/proofofhumanity/package.json
COPY packages/sdk/package.json packages/sdk/package.json
RUN pnpm install --frozen-lockfile --filter @ubi2/proofofhumanity...

COPY apps/proofofhumanity apps/proofofhumanity
COPY packages/sdk packages/sdk
RUN NODE_OPTIONS="--require=/repo/apps/proofofhumanity/scripts/deterministic-next-build.cjs" \
  pnpm --filter @ubi2/proofofhumanity build
RUN node apps/proofofhumanity/scripts/normalize-next-build.mjs
RUN mkdir -p /release/apps/proofofhumanity/.next \
  && cp -a apps/proofofhumanity/.next/standalone/. /release/ \
  && cp -a apps/proofofhumanity/.next/static /release/apps/proofofhumanity/.next/static \
  && cp -a apps/proofofhumanity/public /release/apps/proofofhumanity/public \
  && find /release \
  -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:9a052c12c6501f1248b682bf6d022276220cb2a65416d215e0973527394d1552 AS runtime

ARG POH_SOURCE_REVISION

LABEL org.opencontainers.image.source="https://github.com/DemocracyEarth/ubi2" \
  org.opencontainers.image.revision="${POH_SOURCE_REVISION}" \
  org.opencontainers.image.title="Proof of Humanity Quick Launch API" \
  org.opencontainers.image.description="Transaction-disabled Base Sepolia Quick Launch API candidate"

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

WORKDIR /app
COPY --from=builder --chown=node:node /release/ ./

WORKDIR /app/apps/proofofhumanity
EXPOSE 3000
CMD ["server.js"]
