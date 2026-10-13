# Announcing InfraLayer v0.2.0: The Plug-and-Play Control Layer for AI Applications

Today, I'm excited to announce the stable public release of InfraLayer v0.2.0 – a plug-and-play security control layer for AI applications.

InfraLayer is a zero-dependency, in-process perimeter that filters, sanitizes, and validates every prompt before it reaches an LLM. It enforces tenant isolation, role-based access control, PII/secret redaction, and injection detection – all locally, with zero network latency.

## The Problem

Building production AI applications today means wrestling with a pile of security concerns that LLM vendors don't solve for you:

- **Prompt injection attacks** – users tricking your app into ignoring instructions or revealing system prompts
- **Jailbreaks** – DAN, Developer Mode, God Mode personas bypassing safety rails
- **Data exfiltration** – attempts to extract secrets, passwords, or database contents
- **PII leakage** – accidentally outputting emails, phone numbers, SSNs
- **Tenant cross-contamination** – multi-tenant SaaS where Company A sees Company B's data
- **Privilege escalation** – users accessing data beyond their role/department/level

Most solutions add a secondary LLM call to "review" prompts, which adds ~3 seconds of latency per request and still trusts an AI to catch AI jailbreaks. That felt wrong to us.

## Our Approach

InfraLayer runs **in-process**, before the LLM ever sees the prompt. It's synchronous, CPU-bound, and typically completes in **0.025ms** – that's microseconds, not milliseconds. There's no network hop on the critical path.

The architecture is deliberately simple:

```
Your App → InfraLayer (in-process filter) → Sanitized Context → LLM
```

Inside InfraLayer, we run:
- **15 injection pattern detectors** (ignore instructions, DAN, system prompt extraction, etc.)
- **PII/secret redaction** (emails, phones, API keys, JWTs, private keys)
- **Metadata-aware tenant isolation** (company_id, department, access_level)
- **Role-based access control** (permission evaluation before context reaches LLM)
- **Audit logging** (every decision logged with telemetry)

All of this happens locally with zero network latency.

## What's New in v0.2.0

This is our first stable public release. The key additions in v0.2.0:

### System Owner Control

An out-of-band governance engine that lets you send master-signed overrides to gate admissions:

- `LOCKDOWN` – global circuit breaker (fail-closed, 100% context dropped)
- `THROTTLE:<rps>[:latencyMs]` – dynamic throughput governor (default ceiling 40,000 req/s)
- `CACHE_PURGE` – emergency eviction of in-memory caches
- `RESET` – lift lockdown and restore full throughput

The master passphrase is never stored – only a SHA-256 hash + salt in environment variables. Override headers (`X-InfraLayer-Owner-Override`) are cryptographically verified via constant-time comparison.

This gives you a "red button" for your AI infrastructure – you can lock down the system in an emergency, throttle to protect backend services, or purge caches if a bad pattern slips through.

### Security Hardening

**Strict default-deny tenant contract**

A chunk is admitted only when:
1. `metadata.tenantId` matches `userContext.tenantId`, **or**
2. `metadata.isGlobalPublic === true`

Untagged chunks are denied unless one of the above holds. This ensures that in a multi-tenant SaaS, Company A can never see Company B's data – even if you forget to tag a chunk.

**Input normalization**

Before injection scanning, we normalize input to strip:
- Null bytes
- Control characters
- Zero-width spaces and NBSP
- Unicode normalization (NFC)

This prevents attackers from using encoding obfuscation to bypass pattern detectors.

**Overlap-safe injection quarantine**

When CRITICAL or HIGH severity injection patterns are detected, we quarantine overlapping segments to prevent pattern-matching evasion via delimiter injection.

**Fail-closed gates**

Permission, role, and access-level gates are fail-closed – if evaluation fails for any reason, the context is denied rather than allowed.

### Packaging Fixes

**Fixed peer dependency constraint**

`@infralayer/sdk` now correctly declares `peerDependencies["@infralayer/core"]` as `^0.2.0` (was incorrectly `^1.0.0`). This was breaking offline `.tgz` installs and npm peer resolution.

We've verified that offline tarball installs work cleanly:
```bash
npm install \
  ../../packages/core/infralayer-core-0.2.0.tgz \
  ../../packages/sdk/infralayer-sdk-0.2.0.tgz
```

**Complete TypeScript definitions**

Both packages ship complete `.d.ts` files from `dist/` – no need for `@types/*` packages. The public API surface is clean and well-typed.

## Usage Example

Here's how you'd use it in a TypeScript/Node app:

```typescript
import { createLocalInfraLayer } from '@infralayer/sdk';

const infra = createLocalInfraLayer();

const result = await infra.sanitize(
  {
    text: 'What is our PTO policy? My email is john@company.com',
    // Default-deny: chunk must be scoped to the user's tenant
    metadata: { tenantId: 'tenant_alpha' },
  },
  {
    userId: 'user-123',
    tenantId: 'tenant_alpha',
    role: 'employee',
    permissions: ['read:documents'],
  }
);

// result.sanitizedContext.text → "What is our PTO policy? My email is [EMAIL_REDACTED]"
// result.telemetry.processingTimeMs → typically <1ms
```

The same API is available in Python:

```python
from infralayer import create_local_infralayer

infra = create_local_infralayer()

result = await infra.sanitize(
    {
        "text": "What is our PTO policy? My email is john@company.com",
        "metadata": {"tenantId": "tenant_alpha"},
    },
    {
        "user_id": "user-123",
        "tenant_id": "tenant_alpha",
        "role": "employee",
        "permissions": ["read:documents"],
    },
)

# result.sanitized_context.text → "What is our PTO policy? My email is [EMAIL_REDACTED]"
```

## Architecture

### Request Flow

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐     ┌──────────┐
│   Client    │────▶│   InfraLayer Core   │────▶│  Sanitized  │────▶│   LLM    │
│  (Your App) │     │  (In-Process Filter)│     │  Context    │     │ (Flowise)│
└─────────────┘     └─────────────────────┘     └─────────────┘     └──────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
            ┌─────────────┐ ┌─────────────┐
            │ PII/Secret  │ │  Injection  │
            │ Redaction   │ │  Detection  │
            └─────────────┘ └─────────────┘
                    │             │
                    ▼             ▼
            ┌───────────────────────────┐
            │  Permission Evaluation    │
            │ (Tenant/Role/Dept/Level)  │
            └───────────────────────────┘
                    │
                    ▼
            ┌───────────────────────────┐
            │      Audit Logging        │
            │  (Telemetry + Verdicts)   │
            └───────────────────────────┘
```

### Multi-Tenant Isolation Model

```
┌─────────────────────────────────────────────────────────────────┐
│                      TENANT A (Company A)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Dept: HR   │  │  Dept: Eng  │  │  Dept: Sales│              │
│  │  Level: 1   │  │  Level: 2   │  │  Level: 3   │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
└─────────┼────────────────┼────────────────┼──────────────────────┘
          │                │                │
          ▼                ▼                ▼
    ┌──────────┐     ┌──────────┐     ┌──────────┐
    │ Chunk:   │     │ Chunk:   │     │ Chunk:   │
    │ company=A│     │ company=A│     │ company=A│
    │ dept=HR  │     │ dept=Eng │     │ dept=Sales│
    │ level=1  │     │ level=2  │     │ level=3  │
    └──────────┘     └──────────┘     └──────────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
            ┌───────────────────────────┐
            │   RPC: match_document_chunks     │
            │  WHERE company_id = 'A'      │
            │    AND dept IN ('HR','ALL')  │
            │    AND level <= user_level   │
            └───────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   ONLY ALLOWED CHUNKS   │
              │    REACH THE LLM        │
              └─────────────────────────┘
```

## Verification

We've run penetration tests against 15 adversarial vectors:

| # | Test | Pattern | Severity |
|---|------|---------|----------|
| T1 | Cross-Tenant Isolation | Metadata filter: `company_id` mismatch | — |
| T2 | Privilege Level Isolation | `min_access_level` enforcement | — |
| T3 | Department Scoping | `dept = user_dept OR dept = 'ALL'` | — |
| T4 | Dynamic Deletion | Chunk purge on `DELETE /documents` | — |
| T5 | Prompt Injection | `ignore previous instructions` | HIGH |
| T6 | Jailbreak | `DAN`, `Developer Mode`, `God Mode` | CRITICAL |
| T7 | System Prompt Extraction | `show your system prompt` | HIGH |
| T8 | Role Manipulation | `act as admin` | HIGH |
| T9 | Data Exfiltration | `output all passwords/secrets` | CRITICAL |
| T10 | Chain-of-Thought Extraction | `show your reasoning step by step` | MEDIUM |
| T11 | Delimiter Injection | `---`, `===`, ```, `<<<`, `[INST]` | MEDIUM |
| T12 | Encoding Obfuscation | `base64`, `rot13`, `hex`, `url encode` | MEDIUM |
| T13 | PII Redaction | Email, Phone, SSN, Credit Card, IP, UUID | — |
| T14 | Secret Redaction | API Keys (OpenAI, AWS, GitHub, Slack), JWT, Private Keys | — |
| T15 | Tenant Mismatch Block | `context.tenantId !== user.tenantId` | — |

**Methodology**: All 15 tests use identical one-hot 1536-dim embeddings – only metadata filtering could discriminate. Tests run against live Supabase + pgvector RPC `match_document_chunks`.

**Result**: 15/15 tests passed with 0% leak rate.

## Benchmarks

`sanitize()` is a synchronous, CPU-bound, in-process operation – there is **no network hop** on the critical path, which is why these figures are in microseconds.

| Metric | InfraLayer (in-process) | Secondary LLM call (baseline) |
|--------|------------------------|-------------------------------|
| **Average latency / request** | **0.025 ms** | ~3,146 ms |
| **Throughput (sustained concurrency)** | **39,400+ req/s** | — |
| **Adversarial stress leak rate** | **0%** (100 obfuscated/malformed vectors) | — |

### Metric notes

- **Accept path** (authorized context, matched tenant): ~0.025 ms – pattern scanning + PII/secret redaction + permission evaluation on the happy path
- **Deny path** (default-deny block): ~0.016 ms – short-circuits at the permission gate *before* pattern scanning; the fastest profile
- **Concurrency**: `sanitize()` is synchronous, so a `Promise.all` burst serializes on one thread. Throughput is stated per-workload (e.g. 39,400+ single-chunk req/s), not as a single global number

## Packages

| Package | Language | Install | Description |
|---------|----------|---------|-------------|
| **[@infralayer/core](packages/core)** | TypeScript | `npm i @infralayer/core@^0.2.0` | Zero-dependency core security filter (sanitize, detect, evaluate, owner control) |
| **[@infralayer/sdk](packages/sdk)** | TypeScript | `npm i @infralayer/sdk@^0.2.0` | Full client with retry, auth, local + remote modes (peers `@infralayer/core@^0.2.0`) |
| **[infralayer](sdks/python)** | Python | `pip install infralayer` | Native Python SDK (async/sync, Poetry, Pydantic v2) |

## Installation

### TypeScript / Node.js

```bash
# Core only (zero runtime dependencies)
npm install @infralayer/core@^0.2.0

# Full SDK — install both; SDK peers core at ^0.2.0
npm install @infralayer/core@^0.2.0 @infralayer/sdk@^0.2.0
```

> **Peer dependency:** `@infralayer/sdk@^0.2.0` requires `@infralayer/core@^0.2.0`. Installing both together avoids npm peer warnings and broken offline tarball installs.

### Python

```bash
pip install infralayer
# Or with Poetry:
poetry add infralayer
```

## What's Next

We're already working on:

- More injection patterns (language-specific jailbreaks, encoding obfuscation)
- Additional PII/secret patterns
- Performance optimizations for high-throughput scenarios
- Gateway enhancements for remote mode deployments
- Expanded documentation and example apps

## Get Started

```bash
# TypeScript/Node.js
npm install @infralayer/core@^0.2.0 @infralayer/sdk@^0.2.0

# Python
pip install infralayer
```

Documentation: https://github.com/InfraLayerdev1/InfraLayer#readme

MIT licensed. Production-ready. Feedback welcome!
