FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS builder
WORKDIR /app
ARG NEXT_PUBLIC_APP_ENV=development
ARG ENABLE_NEXT_API_PROXY=false
ARG BACKEND_INTERNAL_URL=
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_APP_ENV=${NEXT_PUBLIC_APP_ENV} \
    ENABLE_NEXT_API_PROXY=${ENABLE_NEXT_API_PROXY} \
    BACKEND_INTERNAL_URL=${BACKEND_INTERNAL_URL}
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
RUN mkdir -p /app/.next/cache && \
    chown -R nextjs:nodejs /app/.next/cache

USER nextjs
EXPOSE 3000

CMD ["node", "server.js"]
