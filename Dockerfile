# Multi-stage production Dockerfile for company-ai gateway
# Node.js 20 on Alpine for minimal attack surface

# ============================================================
# STAGE 1: Build / dependency resolution
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy only package manifests first (cache-friendly)
COPY package*.json ./
COPY gateway/package*.json ./gateway/

# Install production dependencies only
RUN npm ci --production --prefix gateway

# ============================================================
# STAGE 2: Production runtime
# ============================================================
FROM node:20-alpine AS runner

# Security: non-root user, drop capabilities
RUN addgroup -g 1001 -S nodejs && \
    adduser -S -u 1001 -G nodejs nextjs

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Copy production node_modules from builder
COPY --from=builder --chown=nextjs:nodejs /app/gateway/node_modules ./gateway/node_modules

# Copy application source
COPY --chown=nextjs:nodejs gateway ./gateway
COPY --chown=nextjs:nodejs index.html ./

# Switch to non-root user
USER nextjs

# Expose the port the gateway binds to (0.0.0.0:3000)
EXPOSE 3000

# Health check: liveness probe
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health/liveness', (r) => { if (r.statusCode !== 200) process.exit(1) }).on('error', () => process.exit(1))"

# Start the gateway
CMD ["node", "gateway/server.js"]