# Show HN: InfraLayer – Plug-and-play AI infrastructure for developers

I'm excited to share InfraLayer v0.2.0, a plug-and-play security control layer for AI applications. It's a zero-dependency, in-process perimeter that filters, sanitizes, and validates every prompt before it reaches an LLM.

## The Problem

Building production AI applications today means wrestling with a pile of security concerns that the LLM vendors don't solve for you:

- **Prompt injection attacks** – users tricking your app into ignoring instructions or revealing system prompts
- **Jailbreaks** – DAN, Developer Mode, God Mode personas bypassing safety rails
- **Data exfiltration** – attempts to extract secrets, passwords, or database contents
- **PII leakage** – accidentally outputting emails, phone numbers, SSNs
- **Tenant cross-contamination** – multi-tenant SaaS where Company A sees Company B's data
- **Privilege escalation** – users accessing data beyond their role/department/level

Most solutions add a secondary LLM call to "review" prompts, which adds ~3 seconds of latency per request and still trusts an AI to catch AI jailbreaks. That felt wrong to us.

## Our Approach

InfraLayer runs **in-process**, before the LLM ever sees the prompt. It's synchronous, CPU-bound, and typically completes in **0.025ms** (that's microseconds, not milliseconds). There's no network hop on the critical path.

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

The master passphrase is never stored – only a SHA-256 hash + salt in environment variables. Override headers (`X-InfraLayer-Owner-Override`) are cryptographically verified.

### Security Hardening
- **Strict default-deny tenant contract**: untagged chunks require matching `tenantId` or `isGlobalPublic`
- **Input normalization** before injection scanning (null bytes, control chars, Unicode NFC)
- **Overlap-safe injection quarantine** for CRITICAL/HIGH severity matches
- **Fail-closed permission/role/access-level gates**

### Packaging Fixes
- Fixed peer dependency constraint: `@infralayer/sdk` now correctly declares `peerDependencies["@infralayer/core"]` as `^0.2.0` (was incorrectly `^1.0.0`)
- Verified offline tarball installs work cleanly
- Complete TypeScript definitions shipped with both packages

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
```

## Packages

- **`@infralayer/core`** – Zero-dependency core filter (TypeScript, npm)
- **`@infralayer/sdk`** – Full client with local + remote modes (TypeScript, npm)
- **`infralayer`** – Native Python SDK (async/sync, Poetry, Pydantic v2)

## Verification

We've run penetration tests against 15 adversarial vectors (metadata isolation, injection patterns, jailbreaks, PII/secret leakage). All tests passed with 0% leak rate. The methodology uses identical one-hot 1536-dim embeddings – only metadata filtering could discriminate, so the tests verify the security perimeter is enforced correctly.

Benchmarks on this machine (Node 24): average latency 0.025ms per request, sustained throughput 39,400+ req/s.

## Open Questions for the HN Community

1. **Secondary LLM calls vs. in-process filtering** – Most commercial solutions we evaluated add a reviewer LLM that adds seconds of latency. We chose in-process pattern matching for speed and determinism. Is this the right tradeoff, or are we missing something?

2. **Tenant isolation at the application layer** – We enforce isolation via metadata tags on document chunks (`company_id`, `department`, `access_level`). This requires your ingestion pipeline to attach ownership metadata before chunks become retrievable. Is this practical, or should we be offering a different approach?

3. **System Owner Control** – The v0.2.0 addition of an out-of-band governance engine lets you send master-signed overrides (LOCKDOWN, THROTTLE, etc.). Is this useful, or over-engineering for a library?

4. **Python vs. TypeScript adoption** – We're seeing roughly equal interest in both language SDKs. Which would you prioritize for future features?

5. **Self-hosted gateway vs. embedded library** – We offer a hosted gateway (Express + Supabase) for remote mode, but most users seem to prefer local mode (embedding the library directly). Should we invest more in the gateway or keep it as an optional deployment pattern?

## Links

- **GitHub**: https://github.com/InfraLayerdev1/InfraLayer
- **npm**: `@infralayer/core@^0.2.0`, `@infralayer/sdk@^0.2.0`
- **PyPI**: `infralayer`
- **Documentation**: https://github.com/InfraLayerdev1/InfraLayer#readme

MIT licensed. Feedback welcome!
