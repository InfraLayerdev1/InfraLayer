# infralayer-sdk

**Version:** `0.2.0`  
**Install:** `npm install infralayer-core@^0.2.0 infralayer-sdk@^0.2.0`

TypeScript/Node client for InfraLayer. Same sanitize / scan / permission surface in **local** (in-process via `infralayer-core`) or **remote** (HTTP) mode, with retry, auth refresh, and health checks.

Part of [InfraLayer](../../README.md) — *plug-and-play AI infrastructure for developers.*

---

## Install

```bash
# Always install core alongside the SDK (peer dependency)
npm install @infralayer/core@^0.2.0 @infralayer/sdk@^0.2.0
```

| Field | Value |
|-------|-------|
| Peer dependency | `@infralayer/core@^0.2.0` |
| Runtime dependency | `axios@^1.6.0` |
| Node.js | `>=20` |
| Types | complete `.d.ts` from `dist/` (`"types": "dist/index.d.ts"`) |

> **v0.2.0 fix:** peer range is `^0.2.0` (not `^1.0.0`). Mismatched peers break offline `.tgz` installs and npm peer resolution.

---

## Quickstart — local mode

```typescript
import { createLocalInfraLayer } from '@infralayer/sdk';

const infra = createLocalInfraLayer();

const result = await infra.sanitize(
  {
    text: 'What is our PTO policy? My email is john@company.com',
    metadata: { tenantId: 'tenant_alpha' },
  },
  {
    userId: 'user-123',
    tenantId: 'tenant_alpha',
    role: 'employee',
    permissions: ['read:documents'],
  }
);

// result.sanitizedContext?.text → PII-redacted prompt
// result.telemetry → processingTimeMs, injectionsDetected, ...
```

---

## Quickstart — remote mode

```typescript
import { createRemoteInfraLayer } from '@infralayer/sdk';

const infra = createRemoteInfraLayer(
  'https://your-gateway.example.com/v1',
  'il_api_xxx',
  {
    userId: 'service-user',
    tenantId: 'tenant_alpha',
    role: 'system',
    permissions: ['read:documents'],
  }
);

const result = await infra.sanitize(
  { text: userInput, metadata: { tenantId: 'tenant_alpha' } }
  // userContext optional when defaultUserContext was set
);
```

---

## Factories

```typescript
import {
  createInfraLayer,
  createLocalInfraLayer,
  createRemoteInfraLayer,
  InfraLayer,
  type InfraLayerConfig,
} from '@infralayer/sdk';

// Explicit config
const client = createInfraLayer({
  localMode: true,
  defaultUserContext: {
    userId: 'svc',
    tenantId: 't1',
    role: 'system',
    permissions: ['read:documents'],
  },
  timeout: 30000,
  maxRetries: 3,
  retryBaseDelay: 1000,
});

// Local-only (wraps createInfraLayerCore)
const local = createLocalInfraLayer(/* optional core config */);

// Remote-only
const remote = createRemoteInfraLayer(apiUrl, apiKey, defaultUserContext?);
```

### `InfraLayerConfig`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `localMode` | `boolean` | `false` when `apiUrl` set; factories set explicitly | Use in-process core |
| `apiUrl` | `string` | — | Remote API base URL |
| `apiKey` | `string` | — | Remote auth |
| `defaultUserContext` | `UserContext` | — | Used when call omits userContext |
| `timeout` | `number` | axios default | Request timeout (ms) |
| `maxRetries` | `number` | — | Retry attempts |
| `retryBaseDelay` | `number` | — | Exponential backoff base (ms) |
| `coreInstance` | `InfraLayerCore` | auto | Custom core for local mode |
| `axiosInstance` | `AxiosInstance` | auto | Custom HTTP client |
| `onRequest` / `onResponse` / `onError` | callbacks | — | Observability hooks |

---

## Client API

### `sanitize(rawContext, userContext?, options?)` → `Promise<SanitizeResult>`

Works in both modes. Local mode calls `@infralayer/core` synchronously under the hood; remote mode `POST`s to `/sanitize` with retries.

```typescript
await infra.sanitize(
  { text: '...', metadata: { tenantId: 'tenant_alpha' } },
  { userId: 'u1', tenantId: 'tenant_alpha', role: 'employee', permissions: ['read:documents'] },
  { strictMode: false, piiDetection: true }
);
```

> **Signature note:** the SDK takes `(rawContext, userContext, options?)`. The core package takes a single `SanitizeOptions` object. Prefer the SDK factories for application code.

### Local-only helpers

| Method | Notes |
|--------|-------|
| `quickSanitize(text, userContext?)` | String → string; local mode only |
| `scanForInjections(text)` | Detection only; local mode only |
| `checkPermission(userContext, requiredPermissions, ...)` | RBAC; local mode only |
| `getCore()` | Underlying `InfraLayerCore` or `null` in remote mode |

### Remote / dual-mode helpers

| Method | Notes |
|--------|-------|
| `authenticate(userContext?)` | Exchange API key for JWT; remote only |
| `healthCheck()` | Local returns `{ status: 'healthy', version: '0.2.0', ... }` |
| `setMode(localMode)` | Switch modes at runtime |
| `setDefaultUserContext(ctx)` | Update default identity |
| `withConfig(overrides)` | Clone client with merged config |

---

## Re-exported core types

For convenience, the SDK re-exports:

`UserContext`, `RawContext`, `SanitizedContext`, `SanitizeOptions`, `SanitizeResult`, `PermissionEvaluation`, `InjectionDetail`, `InjectionPattern`, `SecurityFlag`, `SanitizeTelemetry`

Import advanced core APIs (`SystemOwnerControl`, `createInfraLayerCore`) from `@infralayer/core` directly:

```typescript
import { createLocalInfraLayer } from '@infralayer/sdk';
import { SystemOwnerControl } from '@infralayer/core';

const ownerControl = new SystemOwnerControl();
const infra = createLocalInfraLayer({ ownerControl });
```

---

## Offline / tarball install

When installing from local packs (no registry):

```bash
npm install \
  ../../packages/core/infralayer-core-0.2.0.tgz \
  ../../packages/sdk/infralayer-sdk-0.2.0.tgz
```

Both packages must resolve at `0.2.0` so the SDK peer dependency is satisfied. Verify with the example harness:

```bash
cd examples/test-app && npm run verify
```

---

## Testing

```bash
cd packages/sdk
npm test
npm run build
```

---

## Related

- [`@infralayer/core`](../core/README.md) — zero-dependency filter + SystemOwnerControl
- [Root README](../../README.md)
- [CHANGELOG](../../CHANGELOG.md)

## License

MIT
