# @infralayer/core

**Version:** `0.2.0`  
**Install:** `npm install @infralayer/core@^0.2.0`

Zero-dependency, in-process pre-LLM security filter. Sanitizes context, detects injections, evaluates tenant/role permissions, and exposes the System Owner control plane — all locally, with no network calls.

Part of [InfraLayer](../../README.md) — *plug-and-play AI infrastructure for developers.*

---

## Install

```bash
npm install @infralayer/core@^0.2.0
```

- **Runtime dependencies:** none
- **Node.js:** `>=20`
- **Types:** shipped as complete `.d.ts` from `dist/` (`"types": "dist/index.d.ts"`)

---

## Quickstart

```typescript
import {
  createInfraLayerCore,
  type UserContext,
  type RawContext,
} from '@infralayer/core';

const core = createInfraLayerCore();

const userContext: UserContext = {
  userId: 'user-123',
  tenantId: 'tenant_alpha',
  role: 'employee',
  permissions: ['read:documents'],
  accessLevel: 2,
};

const rawContext: RawContext = {
  text: 'What is our PTO policy? My email is john@company.com',
  // Default-deny: require matching tenantId, or set isGlobalPublic: true
  metadata: { tenantId: 'tenant_alpha' },
};

const result = core.sanitize({
  userContext,
  rawContext,
  options: {
    piiDetection: true,
    secretDetection: true,
    injectionDetection: true,
    roleEvaluation: true,
  },
});

// result.success === true
// result.sanitizedContext.text includes "[EMAIL_REDACTED]"
// result.telemetry.processingTimeMs → in-process latency
```

---

## API

### `createInfraLayerCore(config?)` → `InfraLayerCore`

```typescript
createInfraLayerCore({
  customInjectionPatterns?: InjectionPattern[];
  customPiiPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
  customSecretPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
  roleHierarchy?: Record<string, number>;
  customRules?: Array<(context: string, userContext: UserContext) => SanitizedSegment[]>;
  ownerControl?: SystemOwnerControl;
});
```

### `InfraLayerCore`

| Method | Signature | Notes |
|--------|-----------|-------|
| `sanitize` | `(options: SanitizeOptions) => SanitizeResult` | Main entry — object form with `userContext` + `rawContext` |
| `quickSanitize` | `(text: string, userContext: UserContext) => string` | String in / string out |
| `scanForInjections` | `(text: string) => InjectionDetail[]` | Detection only |
| `checkPermission` | `(userContext, requiredPermissions, requiredRole?, requiredAccessLevel?, requiredDepartment?) => PermissionEvaluation` | Explicit RBAC check |
| `getOwnerControl` | `() => SystemOwnerControl` | Attached governance engine |

### `SanitizeOptions`

```typescript
interface SanitizeOptions {
  userContext: UserContext;
  rawContext: RawContext | RawContext[];
  ownerOverride?: string;           // X-InfraLayer-Owner-Override header value
  ownerOverrideIdentity?: string;   // X-InfraLayer-Owner-Identity claim
  options?: {
    strictMode?: boolean;
    maxContextLength?: number;
    customPatterns?: InjectionPattern[];
    allowedRoles?: string[];
    allowedDepartments?: string[];
    minAccessLevel?: number;
    piiDetection?: boolean;         // default true
    secretDetection?: boolean;      // default true
    injectionDetection?: boolean;   // default true
    roleEvaluation?: boolean;       // default true
  };
}
```

### Shared types

```typescript
interface UserContext {
  userId: string;
  tenantId: string;
  role: string;
  department?: string;
  accessLevel?: number;
  permissions?: string[];
  metadata?: Record<string, unknown>;
}

interface RawContext {
  text: string;
  source?: string;
  metadata?: Record<string, unknown>;
  // Common metadata keys: tenantId, isGlobalPublic, requiredPermissions,
  // requiredRole, minAccessLevel, department
}

interface SanitizeResult {
  success: boolean;
  sanitizedContext?: SanitizedContext;
  permissionEvaluation?: PermissionEvaluation;
  error?: string;
  telemetry: SanitizeTelemetry;
}
```

---

## System Owner Control (v0.2.0)

`SystemOwnerControl` is the out-of-band orchestration / governance layer. It gates admissions before context processing and supports master-signed overrides:

| Action | Effect |
|--------|--------|
| `LOCKDOWN` | Global circuit breaker — fail-closed, drop all context output |
| `THROTTLE:<rps>[:latencyMs]` | Dynamic throughput governor (default ceiling 40,000 req/s) |
| `CACHE_PURGE` | Evict registered in-memory caches / purgeables |
| `RESET` | Lift lockdown and restore full throughput |

```typescript
import {
  createInfraLayerCore,
  SystemOwnerControl,
} from '@infralayer/core';

const ownerControl = new SystemOwnerControl({
  // Optional: load INFRALAYER_OWNER_KEY_HASH / INFRALAYER_OWNER_SALT
  autoLoadEnvFile: true,
});

const core = createInfraLayerCore({ ownerControl });

// Inspect state
const state = core.getOwnerControl().getState();
// state.maxConcurrency, state.lockDown, state.masterKeyConfigured, ...
```

Master passphrase is never stored — only `INFRALAYER_OWNER_KEY_HASH` + `INFRALAYER_OWNER_SALT` (typically in `.env.local`). Invalid or absent override headers are treated as ordinary unprivileged traffic.

Helper scripts (from this package):

```bash
npm run owner-key      # acquire / hash master key
npm run owner-console  # interactive override console
npm run verify:owner   # live verification suite
```

---

## Default-deny tenant contract

A chunk is admitted only when:

1. `metadata.tenantId` matches `userContext.tenantId`, **or**
2. `metadata.isGlobalPublic === true`

Untagged chunks are denied unless one of the above holds. Role, department, access level, and permission checks still apply when `roleEvaluation` is enabled.

---

## Exports

Clean public surface (see `dist/index.d.ts`):

- **Classes / factories:** `InfraLayerCore`, `createInfraLayerCore`, `SystemOwnerControl`
- **Constants:** `DEFAULT_MAX_CONCURRENCY`, `DEFAULT_MIN_CONCURRENCY`
- **Types:** `UserContext`, `RawContext`, `SanitizedContext`, `SanitizeOptions`, `SanitizeResult`, `SanitizeTelemetry`, `PermissionEvaluation`, `InjectionDetail`, `InjectionPattern`, `SecurityFlag`, `OwnerAction`, `OwnerControlState`, `OwnerOverrideResult`, `OwnerAdmission`, `SystemOwnerControlOptions`

---

## Testing

```bash
cd packages/core
npm test
npm run build
```

---

## Related

- [`@infralayer/sdk`](../sdk/README.md) — client with local + remote modes (peer: `@infralayer/core@^0.2.0`)
- [Root README](../../README.md)
- [CHANGELOG](../../CHANGELOG.md)

## License

MIT
