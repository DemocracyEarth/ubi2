FROM node:22.14.0-bookworm-slim AS builder

ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm:$PATH
ENV NEXT_TELEMETRY_DISABLED=1
ENV POH_BUILD_STANDALONE_API=true
ENV NEXT_PUBLIC_SELF_ENDPOINT=https://proofofhumanity.org/api/self-verify
ENV NEXT_PUBLIC_SELF_ENV=staging
ENV NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL=https://sepolia.base.org

RUN corepack enable && corepack prepare pnpm@10.2.1 --activate

WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/proofofhumanity/package.json apps/proofofhumanity/package.json
COPY packages/sdk/package.json packages/sdk/package.json
RUN pnpm install --frozen-lockfile --filter @ubi2/proofofhumanity...

COPY apps/proofofhumanity apps/proofofhumanity
COPY packages/sdk packages/sdk
RUN pnpm --filter @ubi2/proofofhumanity build

FROM node:22.14.0-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

WORKDIR /app
COPY --from=builder --chown=node:node /repo/apps/proofofhumanity/.next/standalone ./
COPY --from=builder --chown=node:node /repo/apps/proofofhumanity/.next/static ./apps/proofofhumanity/.next/static
COPY --from=builder --chown=node:node /repo/apps/proofofhumanity/public ./apps/proofofhumanity/public

USER node
WORKDIR /app/apps/proofofhumanity
EXPOSE 3000
CMD ["node", "server.js"]
