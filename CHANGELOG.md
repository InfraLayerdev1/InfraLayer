# Changelog

All notable changes to InfraLayer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-10-11

Stable public release of `@infralayer/core` and `@infralayer/sdk` — plug-and-play AI infrastructure for developers.

### Added

#### Orchestration & control layer (`@infralayer/core`)

- **`SystemOwnerControl`** — out-of-band master governance engine with SHA-256 constant-time signature verification
- Override actions via `X-InfraLayer-Owner-Override`:
  - `LOCKDOWN` — global circuit breaker (fail-closed; 100% context output dropped)
  - `THROTTLE:<rps>[:latencyMs]` — dynamic throughput governor (default ceiling **40,000** req/s)
  - `CACHE_PURGE` — emergency eviction of registered in-memory caches / purgeables
  - `RESET` — lift lockdown and restore full throughput
- Optional **owner-identity binding** (`X-InfraLayer-Owner-Identity`) so only the bound System Owner can exercise the master channel
- Admission gate at the top of `sanitize()` (`admissionCheck` / `release`) with artificial latency backpressure
- Env enrollment via `INFRALAYER_OWNER_KEY_HASH` + `INFRALAYER_OWNER_SALT` (`.env.local`); passphrase never stored
- Package scripts: `owner-key`, `owner-console`, `verify:owner`

#### Security engine hardening

- Strict **default-deny** tenant contract: untagged chunks require `isGlobalPublic` or an explicit matching `tenantId`
- Input normalization (null bytes, control chars, zero-width / NBSP, Unicode NFC) before injection scanning
- Overlap-safe injection quarantine for CRITICAL/HIGH matches
- Merged PII/secret redaction segments; bounded telemetry
- Fail-closed permission / role / access-level gates

### Fixed

- **Peer dependency constraint:** `@infralayer/sdk` now declares `peerDependencies["@infralayer/core"]` as **`^0.2.0`** (was incorrectly `^1.0.0`, which broke paired offline `.tgz` installs and npm peer resolution)
- Offline pack path verified: `packages/core/infralayer-core-0.2.0.tgz` + `packages/sdk/infralayer-sdk-0.2.0.tgz` install cleanly into `examples/test-app` (`npm run verify` → PASS)

### Changed

- Package versions aligned at **`0.2.0`** across monorepo root, `@infralayer/core`, `@infralayer/sdk`, and gateway
- SDK `healthCheck()` in local mode reports `version: '0.2.0'`
- Documentation updated for public viewing: root README positioning, package READMEs, install pins at `^0.2.0`

### Packaging & TypeScript

- Clean module exports from package entrypoints (`dist/index.js`)
- Complete TypeScript definitions shipped with both packages (`dist/index.d.ts`, `dist/owner-control.d.ts`)
- `"files": ["dist"]` publish surface — no source leakage in the npm pack
- `"engines": { "node": ">=20.0.0" }` enforced on both packages

### Verification (release QA)

| Check | Result |
|-------|--------|
| Core unit suite | PASS (27+) |
| SDK unit suite | PASS (29+) |
| Offline tarball install + `examples/test-app` verify | PASS |
| Penetration vectors (metadata + injection suite) | 15/15 PASS |
| Owner-control live verify | PASS |

### Install

```bash
npm install @infralayer/core@^0.2.0 @infralayer/sdk@^0.2.0
```

---

## [0.1.0] — 2026-08-23

Initial open-core packaging of the pre-LLM security engine.

### Added

- `@infralayer/core` — zero-dependency sanitize / inject / RBAC filter
- `@infralayer/sdk` — local + remote client with axios retry and auth refresh
- Python SDK (`infralayer`) with async/sync clients
- Multi-tenant metadata filtering, PII/secret redaction, injection pattern set
- Example apps (`nextjs-rag`, `fastapi-rag`) and gateway scaffolding

[0.2.0]: https://github.com/InfraLayerdev1/InfraLayer/releases/tag/v0.2.0
[0.1.0]: https://github.com/InfraLayerdev1/InfraLayer/releases/tag/v0.1.0
