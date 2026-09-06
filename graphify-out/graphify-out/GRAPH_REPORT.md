# Graph Report - graphify-out  (2026-08-17)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 123 nodes · 152 edges · 9 communities (7 shown, 2 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 7 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `676a0f74`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- dependencies
- server.js
- seed-demo-tenant.js
- create-tenant.js
- package.json
- billing.js
- logAuditEvent
- buildAuthResponse
- verifyActiveAccountAndToken

## God Nodes (most connected - your core abstractions)
1. `main()` - 12 edges
2. `main()` - 11 edges
3. `logAuditEvent()` - 7 edges
4. `scripts` - 4 edges
5. `fail()` - 3 edges
6. `red()` - 3 edges
7. `fail()` - 3 edges
8. `red()` - 3 edges
9. `createTenantFromCheckout()` - 3 edges
10. `authRateLimiter()` - 3 edges

## Surprising Connections (you probably didn't know these)
- `verifyActiveAccountAndToken()` --calls--> `logAuditEvent()`  [EXTRACTED]
  server.js → server.js  _Bridges community 6 → community 8_

## Import Cycles
- None detected.

## Communities (9 total, 2 thin omitted)

### Community 0 - "dependencies"
Cohesion: 0.08
Nodes (25): axios, bcrypt, cors, dotenv, express, express-rate-limit, helmet, jsonwebtoken (+17 more)

### Community 1 - "server.js"
Cohesion: 0.09
Nodes (15): allowedOrigins, app, axios, bcrypt, cors, {
createClient }, crypto, express (+7 more)

### Community 2 - "seed-demo-tenant.js"
Cohesion: 0.15
Nodes (19): bcrypt, bold(), { createClient }, crypto, DEMO_BUNDLES, DEMO_COMPANY, DEMO_USERS, dim() (+11 more)

### Community 3 - "create-tenant.js"
Cohesion: 0.19
Nodes (17): bcrypt, bold(), { createClient }, crypto, dim(), fail(), generateTempPassword(), green() (+9 more)

### Community 4 - "package.json"
Cohesion: 0.15
Nodes (12): author, description, keywords, license, main, name, scripts, create-tenant (+4 more)

### Community 5 - "billing.js"
Cohesion: 0.20
Nodes (10): { createClient }, createTenantFromCheckout(), crypto, express, generateApiKey(), generateTempPassword(), TODO: Send welcome email with credentials to customerEmail, router (+2 more)

### Community 6 - "logAuditEvent"
Cohesion: 0.29
Nodes (7): apiRateLimiter(), authRateLimiter(), getClientIp(), ingestDocumentWithMetadata(), logAuditEvent(), logCrashTelemetry(), requireAdmin()

## Knowledge Gaps
- **56 isolated node(s):** `axios`, `bcrypt`, `cors`, `dotenv`, `express` (+51 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `dependencies` connect `dependencies` to `package.json`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **What connects `axios`, `bcrypt`, `cors` to the rest of the system?**
  _56 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `dependencies` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._
- **Should `server.js` be split into smaller, more focused modules?**
  _Cohesion score 0.08695652173913043 - nodes in this community are weakly interconnected._
- **Should `seed-demo-tenant.js` be split into smaller, more focused modules?**
  _Cohesion score 0.14761904761904762 - nodes in this community are weakly interconnected._