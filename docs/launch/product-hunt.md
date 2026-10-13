# Product Hunt Launch: InfraLayer v0.2.0

## Tagline
Plug-and-play AI infrastructure for developers

## Description
InfraLayer is a zero-dependency, in-process security control layer for AI applications. It filters, sanitizes, and validates every prompt before it reaches an LLM – all locally, with zero network latency.

**What it solves:**
- Prompt injection attacks and jailbreaks
- PII and secret leakage
- Tenant cross-contamination in multi-tenant SaaS
- Privilege escalation attempts
- Data exfiltration risks

**How it works:**
Run InfraLayer in-process before your LLM call. It uses pattern matching, metadata filtering, and role-based access control to sanitize context – typically in 0.025ms. No secondary LLM calls, no network hops on the critical path.

**What's new in v0.2.0:**
- System Owner Control – out-of-band governance engine with master-signed overrides (LOCKDOWN, THROTTLE, CACHE_PURGE)
- Strict default-deny tenant contract
- Input normalization and overlap-safe injection quarantine
- Fixed peer dependency constraints for clean offline installs
- Complete TypeScript definitions shipped

**Packages:**
- `@infralayer/core` – Zero-dependency core filter (TypeScript, npm)
- `@infralayer/sdk` – Full client with local + remote modes (TypeScript, npm)
- `infralayer` – Native Python SDK (async/sync, Poetry, Pydantic v2)

**Verification:**
- 15/15 penetration test vectors passed (metadata isolation, injection patterns, jailbreaks, PII/secret leakage)
- 0% leak rate across 100 adversarial vectors
- Benchmarks: 0.025ms avg latency, 39,400+ req/s sustained throughput

MIT licensed. Ready for production use.

## Key Features

- **Zero network latency** – In-process filtering, typically completes in 0.025ms
- **15 injection pattern detectors** – Ignore instructions, DAN, jailbreaks, system prompt extraction
- **PII/secret redaction** – Emails, phones, SSNs, API keys, JWTs, private keys
- **Metadata-aware tenant isolation** – Company_id, department, access_level filtering
- **Role-based access control** – Permission evaluation before context reaches LLM
- **Audit logging** – Every decision logged with telemetry
- **System Owner Control** – Master-signed overrides (LOCKDOWN, THROTTLE, CACHE_PURGE)
- **TypeScript + Python** – Complete SDKs for both languages
- **Zero dependencies** – Core package has no runtime dependencies
- **Production-ready** – 15/15 penetration tests passed, MIT licensed

## Maker's Comment

Hi everyone! I'm excited to launch InfraLayer v0.2.0 today.

## The Story

I built InfraLayer after watching teams struggle with AI security in production. Every company adding LLMs to their products hit the same wall: "How do we prevent prompt injection? How do we stop users from seeing each other's data? What about PII leakage?"

The solutions I found were either:
1. **Add a secondary LLM call** to "review" prompts – adds ~3 seconds of latency, still trusts an AI to catch AI jailbreaks
2. **Build custom sanitization** – reinventing the wheel, hard to maintain, usually misses edge cases
3. **Commercial guardrails services** – expensive, network latency, vendor lock-in

None of these felt right. So I built something different: a plug-and-play library that runs in-process, before the LLM ever sees the prompt.

## Design Philosophy

Three principles guided the architecture:

1. **Speed matters** – If security adds seconds of latency, teams won't use it. In-process filtering lets us run in microseconds.

2. **Determinism over AI** – Pattern matching and metadata rules are predictable. You know exactly what will be blocked or redacted.

3. **Zero dependencies** – Security libraries shouldn't pull in hundreds of transitive dependencies. The core package has literally zero runtime deps.

## What v0.2.0 Adds

This is our first stable public release. The big addition is **System Owner Control** – an out-of-band governance engine that lets you send master-signed overrides to gate admissions. Think of it as a "red button" for your AI infrastructure: LOCKDOWN to drop all context, THROTTLE to cap throughput, CACHE_PURGE to evict caches.

We also hardened the security engine with strict default-deny tenant contracts, input normalization, and overlap-safe injection quarantine.

## Who This Is For

- **Developers building AI-powered features** – Drop in InfraLayer before your LLM call, get security guarantees
- **Multi-tenant SaaS teams** – Enforce tenant isolation via metadata tags on document chunks
- **Enterprise AI platforms** – Role-based access control, audit logging, compliance-ready
- **Anyone who doesn't want to reinvent AI security** – We've done the hard work

## Verification

We've run penetration tests against 15 adversarial vectors (metadata isolation, injection patterns, jailbreaks, PII/secret leakage). All tests passed with 0% leak rate. The methodology uses identical one-hot 1536-dim embeddings – only metadata filtering could discriminate, so the tests verify the security perimeter is enforced correctly.

Benchmarks on this machine (Node 24): average latency 0.025ms per request, sustained throughput 39,400+ req/s.

## What's Next

We're already working on:
- More injection patterns (language-specific jailbreaks, encoding obfuscation)
- Additional PII/secret patterns
- Performance optimizations for high-throughput scenarios
- Gateway enhancements for remote mode deployments

## Ask

I'd love feedback on:
- The architecture choice (in-process vs. secondary LLM)
- The System Owner Control feature – useful or over-engineering?
- Python vs. TypeScript – which should we prioritize for future features?
- Gateway vs. embedded library – which deployment pattern do you prefer?

Thanks for checking out InfraLayer! I'm here to answer questions and listen to feedback.
