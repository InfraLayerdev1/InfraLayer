/**
 * @fileoverview Targeted tests for SystemOwnerControl — the out-of-band master
 * governance engine (kill-switch, throughput governor, emergency cache purge).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  SystemOwnerControl,
  InfraLayerCore,
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_MIN_CONCURRENCY,
} from './index';

const MASTER_PASSPHRASE = 'correct horse battery staple';
const SALT = '0'.repeat(32); // deterministic per-install salt for tests
const HASH = SystemOwnerControl.hashPassphrase(MASTER_PASSPHRASE, SALT);

function makeControl(options: ConstructorParameters<typeof SystemOwnerControl>[0] = {}) {
  return new SystemOwnerControl({
    ownerKeyHash: HASH,
    ownerSalt: SALT,
    ...options,
  });
}

describe('SystemOwnerControl — signature verification', () => {
  it('generates a valid signature only with the master passphrase', () => {
    const control = makeControl();
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    expect(header).toMatch(/^[0-9a-f]{64}:LOCKDOWN$/);
    expect(control.evaluateOverride(header).authorized).toBe(true);
  });

  it('rejects an invalid signature as unprivileged traffic', () => {
    const control = makeControl();
    const forged = `${'1'.repeat(64)}:LOCKDOWN`;
    const result = control.evaluateOverride(forged);
    expect(result.authorized).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
    expect(result.lockDown).toBe(false);
  });

  it('rejects a malformed header shape', () => {
    const control = makeControl();
    const result = control.evaluateOverride('not-a-signature');
    expect(result.authorized).toBe(false);
    expect(result.reason).toBe('MALFORMED_SIGNATURE');
  });

  it('treats absent headers as unprivileged (no override)', () => {
    const control = makeControl();
    const result = control.evaluateOverride(null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toBe('NO_OVERRIDE_HEADER');
  });

  it('ignores every header when no master key is configured', () => {
    const control = new SystemOwnerControl();
    expect(control.masterKeyConfigured).toBe(false);
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    const result = control.evaluateOverride(header);
    expect(result.authorized).toBe(false);
    expect(result.reason).toBe('MASTER_KEY_NOT_CONFIGURED');
  });

  it('uses constant-time comparison (different-length sigs never crash)', () => {
    const control = makeControl();
    const shortForgery = `${'a'.repeat(63)}:LOCKDOWN`;
    const result = control.evaluateOverride(shortForgery);
    expect(result.authorized).toBe(false);
  });
});

describe('SystemOwnerControl — global circuit breaker (LOCKDOWN)', () => {
  it('trips the kill-switch and fails closed', () => {
    const control = makeControl();
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    const result = control.evaluateOverride(header);
    expect(result.authorized).toBe(true);
    expect(result.applied).toBe(true);
    expect(result.lockDown).toBe(true);
    expect(control.isLockedDown()).toBe(true);
    // While locked down, every admission is denied.
    expect(control.admissionCheck().allowed).toBe(false);
    expect(control.admissionCheck().reason).toBe('SYSTEM_LOCKDOWN');
  });

  it('lifts the kill-switch via a valid RESET', () => {
    const control = makeControl();
    control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN'));
    const reset = control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'RESET'));
    expect(reset.applied).toBe(true);
    expect(control.isLockedDown()).toBe(false);
  });
});

describe('SystemOwnerControl — dynamic throughput governor (THROTTLE)', () => {
  it('scales concurrency from 40000 down to 1 req/s', () => {
    const control = makeControl();
    expect(control.getState().maxConcurrency).toBe(DEFAULT_MAX_CONCURRENCY);

    const th = control.evaluateOverride(
      SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['1'])
    );
    expect(th.applied).toBe(true);
    expect(control.getState().maxConcurrency).toBe(1);

    // Below the 40k ceiling, admissions are granted.
    const full = control.evaluateOverride(
      SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', [String(DEFAULT_MAX_CONCURRENCY)])
    );
    expect(full.applied).toBe(true);
    expect(control.getState().maxConcurrency).toBe(DEFAULT_MAX_CONCURRENCY);
  });

  it('denies admission once the lowered ceiling is saturated', () => {
    const control = makeControl();
    control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['2']));
    expect(control.admissionCheck().allowed).toBe(true);
    expect(control.admissionCheck().allowed).toBe(true);
    const denied = control.admissionCheck();
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe('THROTTLE_CAPACITY_EXCEEDED');
    expect(denied.throttled).toBe(true);
  });

  it('releases admission slots back to the pool', () => {
    const control = makeControl();
    control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['1']));
    expect(control.admissionCheck().allowed).toBe(true);
    expect(control.admissionCheck().allowed).toBe(false);
    control.release();
    expect(control.admissionCheck().allowed).toBe(true);
  });

  it('injects artificial latency backpressure from the header', () => {
    const control = makeControl();
    control.evaluateOverride(
      SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['100', '250'])
    );
    expect(control.getState().artificialLatencyMs).toBe(250);
    // An invalid auth signature never mutates governor state.
    control.evaluateOverride(`${'2'.repeat(64)}:THROTTLE:5:999`);
    expect(control.getState().artificialLatencyMs).toBe(250);
  });

  it('clamps throttles to the 1 rps floor', () => {
    const control = makeControl();
    control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['0']));
    expect(control.getState().maxConcurrency).toBe(DEFAULT_MIN_CONCURRENCY);
  });
});

describe('SystemOwnerControl — emergency cache purge (CACHE_PURGE)', () => {
  it('evicts LRU token, JWT bitmask, and SharedArrayBuffer state on demand', () => {
    const control = makeControl();
    control.registerLruToken('tok-1', 'mapping');
    control.registerJwt('jwt-abc');
    control.registerSharedArrayBuffer('sbuf-1');
    expect(control.getState().lruPurgeCount).toBe(0);

    const result = control.evaluateOverride(
      SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE')
    );
    expect(result.applied).toBe(true);
    const state = control.getState();
    expect(state.lruPurgeCount).toBe(1);
    expect(state.jwtPurgeCount).toBe(1);
    expect(state.sabPurgeCount).toBe(1);
  });

  it('also purges externally registered purgeable resources', () => {
    const control = makeControl();
    let purged = 0;
    control.registerPurgeable('external-cache', () => {
      purged += 10;
      return 10;
    });
    control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE'));
    expect(purged).toBe(10);
  });

  it('never lets a failing external purge block the emergency path', () => {
    const control = makeControl();
    control.registerPurgeable('bad-cache', () => {
      throw new Error('purge failed');
    });
    expect(() =>
      control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE'))
    ).not.toThrow();
  });
});

describe('InfraLayerCore integration — sanitize() Step 0', () => {
  const user = { userId: 'u1', tenantId: 't1', role: 'admin', accessLevel: 5 };

  it('drops 100% of context output on a valid LOCKDOWN override', () => {
    const control = makeControl();
    const core = new InfraLayerCore({ ownerControl: control });
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');

    const result = core.sanitize({
      userContext: user,
      ownerOverride: header,
      rawContext: { text: 'TOP SECRET context that must never leak', metadata: { isGlobalPublic: true } },
    });

    expect(result.sanitizedContext?.text).toContain('LOCKDOWN');
    expect(result.sanitizedContext?.text).not.toContain('TOP SECRET');
    expect(result.sanitizedContext?.sanitizedLength).toBe(0);
    expect(result.sanitizedContext?.securityFlags.some(f => f.flag === 'SYSTEM_LOCKDOWN')).toBe(true);
  });

  it('treats an invalid signature as ordinary unprivileged traffic', () => {
    const control = makeControl();
    const core = new InfraLayerCore({ ownerControl: control });
    const forged = `${'1'.repeat(64)}:LOCKDOWN`;

    const result = core.sanitize({
      userContext: user,
      ownerOverride: forged,
      rawContext: { text: 'What is our PTO policy?', metadata: { isGlobalPublic: true } },
    });

    expect(result.success).toBe(true);
    expect(result.sanitizedContext?.text).toBe('What is our PTO policy?');
    expect(result.sanitizedContext?.securityFlags.some(f => f.flag === 'SYSTEM_LOCKDOWN')).toBe(false);
  });

  it('returns a zero-output marker when the governor ceiling is exhausted', () => {
    const control = makeControl();
    control.setThrottle(0); // clamps to 1
    control.admissionCheck(); // consume the single slot
    const core = new InfraLayerCore({ ownerControl: control });

    const result = core.sanitize({
      userContext: user,
      rawContext: { text: 'Should be dropped under saturation', metadata: { isGlobalPublic: true } },
    });

    expect(result.sanitizedContext?.text).toContain('capacity');
    expect(result.sanitizedContext?.securityFlags.some(f => f.flag === 'SYSTEM_THROTTLED')).toBe(true);
    expect(result.sanitizedContext?.sanitizedLength).toBe(0);
  });

  it('leaves a default core unlocked and at full throughput', () => {
    const core = new InfraLayerCore();
    const result = core.sanitize({
      userContext: user,
      rawContext: { text: 'normal request', metadata: { isGlobalPublic: true } },
    });
    expect(result.sanitizedContext?.text).toBe('normal request');
    expect(core.getOwnerControl().getState().maxConcurrency).toBe(DEFAULT_MAX_CONCURRENCY);
    expect(core.getOwnerControl().isLockedDown()).toBe(false);
  });
});

describe('SystemOwnerControl — env loading & key configuration', () => {
  it('loads hash and salt from a dotenv-style file', () => {
    const tmp = path.join(os.tmpdir(), `ownerctl-${Date.now()}-${Math.random().toString(36).slice(2)}.env.local`);
    fs.writeFileSync(tmp, `# generated\nINFRALAYER_OWNER_KEY_HASH='${HASH}'\nINFRALAYER_OWNER_SALT="${SALT}"\n\nOTHER_VAR=keep\n`);
    try {
      const control = new SystemOwnerControl({ autoLoadEnvFile: true, envFilePath: tmp });
      expect(control.masterKeyConfigured).toBe(true);
      expect(control.ownerSaltHex).toBe(SALT);
      expect(control.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN')).authorized).toBe(true);
    } finally {
      fs.unlinkSync(tmp);
    }
  });

  it('returns false when the env file is absent', () => {
    const control = new SystemOwnerControl();
    expect(control.loadFromEnvFile('/definitely/missing/.env.local')).toBe(false);
  });

  it('rejects malformed key/salt input on configure', () => {
    const control = new SystemOwnerControl();
    control.configure('not-hex!!', 'zzzz');
    expect(control.masterKeyConfigured).toBe(false);
    expect(control.ownerSaltHex).toBeNull();
  });
});

describe('SystemOwnerControl — programmatic governor API', () => {
  it('setThrottle / setLatency map into state', () => {
    const c = makeControl();
    c.setThrottle(7.9);
    expect(c.getState().maxConcurrency).toBe(7);
    c.setThrottle(999999);
    expect(c.getState().maxConcurrency).toBe(DEFAULT_MAX_CONCURRENCY);
    c.setLatency(-5);
    expect(c.getState().artificialLatencyMs).toBe(0);
    c.setLatency(123.9);
    expect(c.getState().artificialLatencyMs).toBe(123);
  });

  it('applyBackpressure resolves immediately with zero latency and waits when set', async () => {
    const c = makeControl();
    await c.applyBackpressure();
    c.setLatency(25);
    const t0 = Date.now();
    await c.applyBackpressure();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(20);
  });
});

describe('SystemOwnerControl — override edge cases', () => {
  it('records the override timestamp on authorized actions', () => {
    const c = makeControl();
    expect(c.getState().lastOverrideAt).toBeNull();
    c.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE'));
    expect(c.getState().lastOverrideAction).toBe('CACHE_PURGE');
    expect(c.getState().lastOverrideAt).not.toBeNull();
  });

  it('reports unknown actions as authorized but unapplied', () => {
    const c = makeControl();
    const r = c.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'HACK'));
    expect(r.authorized).toBe(true);
    expect(r.applied).toBe(false);
    expect(r.reason).toBe('UNKNOWN_ACTION');
    // The perimeter is not affected by an unknown (authorized) action.
    expect(c.isLockedDown()).toBe(false);
  });

  it('ignores THROTTLE with an invalid rate param', () => {
    const c = makeControl();
    const r = c.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['abc']));
    expect(r.applied).toBe(false);
    expect(r.reason).toBe('INVALID_THROTTLE_PARAM');
    expect(c.getState().maxConcurrency).toBe(DEFAULT_MAX_CONCURRENCY);
  });

  it('signOverride composes params into the header value', () => {
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'THROTTLE', ['5', '10']);
    expect(header).toBe(`${HASH}:THROTTLE:5:10`);
  });

  it('bounds the LRU token map at 1000 entries and purges cleanly', () => {
    const c = makeControl();
    for (let i = 0; i < 1005; i++) c.registerLruToken(`k${i}`, 'v');
    expect(c.getLruCacheSize()).toBeLessThanOrEqual(1000);
    const r = c.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE'));
    expect(r.applied).toBe(true);
    expect(c.getLruCacheSize()).toBe(0);
  });

  it('registers external purgeables and they are counted in the purge', () => {
    const c = makeControl();
    c.registerPurgeable('ext-a', () => 2);
    const r = c.evaluateOverride(SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE'));
    expect(r.message).toContain('5 resources evicted'); // 3 internal + 2 external
  });
});

describe('SystemOwnerControl — owner-identity gate (bound to one name)', () => {
  const OWNER = 'Evan Alvino';
  const bound = () => makeControl({ ownerIdentity: OWNER });

  it('requires the bound identity on top of a valid signature', () => {
    const c = bound();
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    expect(c.evaluateOverride(header, OWNER).authorized).toBe(true);
    expect(c.evaluateOverride(header, OWNER).lockDown).toBe(true);
  });

  it('rejects a valid signature with the WRONG identity', () => {
    const c = bound();
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    const r = c.evaluateOverride(header, 'Someone Else');
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('IDENTITY_MISMATCH');
    expect(r.lockDown).toBe(false);
    expect(c.isLockedDown()).toBe(false);
  });

  it('rejects a valid signature with a MISSING identity claim', () => {
    const c = bound();
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    const r = c.evaluateOverride(header, null);
    expect(r.authorized).toBe(false);
    expect(r.reason).toBe('IDENTITY_REQUIRED');
  });

  it('exposes the bound name and binding flag', () => {
    const c = bound();
    expect(c.ownerName).toBe(OWNER);
    expect(c.identityBound).toBe(true);
    expect(c.getState().ownerIdentity).toBe(OWNER);
  });

  it('keeps the master key usable without a binding when none is configured', () => {
    const c = makeControl(); // no ownerIdentity -> no binding
    expect(c.identityBound).toBe(false);
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'CACHE_PURGE');
    expect(c.evaluateOverride(header, 'anyone').authorized).toBe(true);
  });

  it('integration: sanitize() enforces the identity claim via ownerOverrideIdentity', () => {
    const identity = bound();
    const core = new InfraLayerCore({ ownerControl: identity });
    const header = SystemOwnerControl.signOverride(MASTER_PASSPHRASE, SALT, 'LOCKDOWN');
    const opts = (ident: string | undefined) => ({
      userContext: { userId: 'u', tenantId: 't', role: 'admin' },
      rawContext: { text: 'confidential payload', metadata: { isGlobalPublic: true } },
      ownerOverride: header,
      ...(ident ? { ownerOverrideIdentity: ident } : {}),
    });

    // Wrong identity -> signature ignored, request proceeds normally.
    const wrong = core.sanitize(opts('Someone Else'));
    expect(wrong.sanitizedContext?.text).toBe('confidential payload');
    // Correct identity -> LOCKDOWN drops 100% of output.
    const right = core.sanitize(opts(OWNER));
    expect(right.sanitizedContext?.text).toContain('LOCKDOWN');
    expect(right.sanitizedContext?.text).not.toContain('confidential');
    expect(right.sanitizedContext?.sanitizedLength).toBe(0);
  });
});