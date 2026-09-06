/**
 * @fileoverview System Owner Control — out-of-band master governance engine.
 *
 * Grants the System Owner exclusive, emergency override authority over the
 * InfraLayer perimeter via a SHA-256 master-key signature carried in the
 * `X-InfraLayer-Owner-Override` request header:
 *
 *   X-InfraLayer-Owner-Override: <signature>:<ACTION>[:param1[:param2]]
 *   signature = SHA-256(hex(salt) + ':' + passphrase)
 *
 * The master passphrase is NEVER stored. Only `INFRALAYER_OWNER_KEY_HASH`
 * (and the random per-install `INFRALAYER_OWNER_SALT`) live in `.env.local`.
 * Verification is a constant-time comparison against that stored hash, so a
 * forged, expired, or unauthenticated header is treated as ordinary
 * unprivileged traffic — the override channel is strictly out-of-band.
 *
 * Three override powers (only reachable with a valid master signature):
 *   1. Global Circuit Breaker (kill-switch)  ->  LOCKDOWN
 *   2. Dynamic Throughput Governor           ->  THROTTLE:<rps>[:latencyMs]
 *   3. Emergency Cache Purge                 ->  CACHE_PURGE
 *
 * A fourth power, RESET, clears the override state (restores throughput,
 * lifts lockdown) without re-running the interactive key acquisition.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Default concurrency ceiling — 40,000 req/sec at full capacity. */
export const DEFAULT_MAX_CONCURRENCY = 40000;

/** The governor can scale concurrency as low as this (1 req/sec). */
export const DEFAULT_MIN_CONCURRENCY = 1;

export type OwnerAction = 'LOCKDOWN' | 'THROTTLE' | 'CACHE_PURGE' | 'RESET';

export interface OwnerControlState {
  /** True while the global circuit breaker is tripped (fail-closed). */
  lockDown: boolean;
  /** Current concurrency ceiling in req/sec (40000 -> 1). */
  maxConcurrency: number;
  /** Number of in-flight sanitize admissions. */
  activeConcurrency: number;
  /** Artificial latency (ms) injected as backpressure. */
  artificialLatencyMs: number;
  defaultMaxConcurrency: number;
  minConcurrency: number;
  lruPurgeCount: number;
  jwtPurgeCount: number;
  sabPurgeCount: number;
  lastOverrideAction: string | null;
  lastOverrideAt: string | null;
  masterKeyConfigured: boolean;
  /** The sole named identity bound to this master key (null = no binding). */
  ownerIdentity: string | null;
}

export interface OwnerOverrideResult {
  authorized: boolean;
  action: string | null;
  applied: boolean;
  /** True when the kill-switch is engaged — the caller must fail closed. */
  lockDown: boolean;
  state: OwnerControlState;
  reason: string;
  message: string;
}

export interface OwnerAdmission {
  allowed: boolean;
  reason: string;
  throttled: boolean;
  maxConcurrency: number;
  activeConcurrency: number;
}

export interface SystemOwnerControlOptions {
  /** Hex SHA-256(salt + ':' + passphrase). Mutually governs with ownerSalt. */
  ownerKeyHash?: string | null;
  /** Hex per-install salt used when computing the hash. */
  ownerSalt?: string | null;
  /**
   * The sole named identity allowed to exercise the master key. When set, the
   * override channel requires BOTH a valid master signature AND a matching
   * owner-identity claim — any other name is treated as unprivileged traffic.
   */
  ownerIdentity?: string | null;
  /** Auto-load INFRALAYER_OWNER_KEY_HASH / INFRALAYER_OWNER_SALT from disk. */
  autoLoadEnvFile?: boolean;
  /** Path to the .env.local file (default: <cwd>/.env.local). */
  envFilePath?: string;
  /** Concurrency ceiling at full capacity (default 40000). */
  maxConcurrencyDefault?: number;
  /** Floor the governor can throttle down to (default 1). */
  minConcurrency?: number;
}

interface LruEntry {
  value: string;
  expiresAt: number;
  lastAccess: number;
}

interface PurgeableResource {
  name: string;
  purge: () => number;
}

/**
 * Master governance engine. Holds the owner override state machine, the
 * admission/throughput governor, and the emergency cache-purge registry.
 */
export class SystemOwnerControl {
  private ownerKeyHash: string | null = null;
  private ownerSalt: string | null = null;
  private ownerIdentity: string | null = null;

  private lockDown = false;
  private defaultMaxConcurrency: number;
  private minConcurrency: number;
  private maxConcurrency: number;
  private activeConcurrency = 0;
  private artificialLatencyMs = 0;

  // Demonstration purgeable in-memory state: an LRU token map, a JWT
  // revocation bitmask (as a compact Set of revoked ids), and a set of
  // SharedArrayBuffer memory states. External modules may register their own
  // purgeable resources so a single CACHE_PURGE evicts the whole perimeter.
  private lruTokenMap = new Map<string, LruEntry>();
  private jwtBitmask = new Set<string>();
  private sharedArrayBufferStates = new Map<string, SharedArrayBuffer>();
  private purgeables: PurgeableResource[] = [];

  private lruPurgeCount = 0;
  private jwtPurgeCount = 0;
  private sabPurgeCount = 0;
  private lastOverrideAction: string | null = null;
  private lastOverrideAt: string | null = null;
  private lastAdmissionAt = 0;

  constructor(options: SystemOwnerControlOptions = {}) {
    this.defaultMaxConcurrency = options.maxConcurrencyDefault ?? DEFAULT_MAX_CONCURRENCY;
    this.minConcurrency = options.minConcurrency ?? DEFAULT_MIN_CONCURRENCY;
    this.maxConcurrency = this.defaultMaxConcurrency;
    this.configure(options.ownerKeyHash ?? null, options.ownerSalt ?? null);
    this.ownerIdentity = options.ownerIdentity && options.ownerIdentity.trim().length > 0 ? options.ownerIdentity.trim() : null;
    if (options.autoLoadEnvFile === true) {
      this.loadFromEnvFile(options.envFilePath);
    }
  }

  // ---------------------------------------------------------------------------
  // Key / salt management
  // ---------------------------------------------------------------------------

  /** Generate a fresh random per-install salt (32 hex chars). */
  static generateSalt(): string {
    return randomBytes(16).toString('hex');
  }

  /** Compute SHA-256(hex(salt) + ':' + passphrase) as lowercase hex. */
  static hashPassphrase(passphrase: string, saltHex: string): string {
    return createHash('sha256').update(saltHex).update(':').update(passphrase).digest('hex');
  }

  /**
   * Produce a full `X-InfraLayer-Owner-Override` header value for the given
   * action. Only callable with knowledge of the master passphrase.
   */
  static signOverride(passphrase: string, saltHex: string, action: string, params: string[] = []): string {
    const signature = SystemOwnerControl.hashPassphrase(passphrase, saltHex);
    const tail = params.length > 0 ? ':' + params.join(':') : '';
    return `${signature}:${action.toUpperCase()}${tail}`;
  }

  /** Set (or clear) the configured master key hash + salt. */
  configure(ownerKeyHash: string | null, ownerSalt: string | null): void {
    this.ownerKeyHash = ownerKeyHash && /^[0-9a-f]{64}$/i.test(ownerKeyHash) ? ownerKeyHash.toLowerCase() : null;
    this.ownerSalt = ownerSalt && /^[0-9a-f]+$/i.test(ownerSalt) ? ownerSalt.toLowerCase() : null;
  }

  get masterKeyConfigured(): boolean {
    return this.ownerKeyHash !== null;
  }

  /** The per-install salt this control verifies against (needed by sign tooling). */
  get ownerSaltHex(): string | null {
    return this.ownerSalt;
  }

  /** The sole named identity bound to this master key (null = no binding). */
  get ownerName(): string | null {
    return this.ownerIdentity;
  }

  /** True when an owner-identity binding is enforced on the override channel. */
  get identityBound(): boolean {
    return this.ownerIdentity !== null;
  }

  /** Constant-time compare of a presented identity against the bound owner name. */
  private verifyIdentity(identity: string | null): boolean {
    if (!this.ownerIdentity || identity === null) return false;
    const a = Buffer.from(identity, 'utf8');
    const b = Buffer.from(this.ownerIdentity, 'utf8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  /**
   * Load INFRALAYER_OWNER_KEY_HASH / INFRALAYER_OWNER_SALT from a dotenv-style
   * file (default <cwd>/.env.local). Zero-dependency — a tiny parser replaces
   * the `dotenv` package. Returns false when no hash could be read.
   */
  loadFromEnvFile(filePath?: string): boolean {
    const target = filePath ?? path.resolve(process.cwd(), '.env.local');
    let content: string;
    try {
      content = fs.readFileSync(target, 'utf8');
    } catch {
      return false;
    }
    const vars = this.parseDotEnv(content);
    const hash = vars['INFRALAYER_OWNER_KEY_HASH'];
    if (!hash) return false;
    this.configure(hash, vars['INFRALAYER_OWNER_SALT'] ?? null);
    const name = vars['INFRALAYER_OWNER_NAME'];
    this.ownerIdentity = name && name.trim().length > 0 ? name.trim() : null;
    return true;
  }

  private parseDotEnv(content: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      let key = line.slice(0, eq).trim();
      if (key.startsWith('export ')) key = key.slice(7).trim();
      let val = line.slice(eq + 1).trim();
      if (
        (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
        (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
      ) {
        val = val.slice(1, -1);
      }
      out[key] = val;
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Override evaluation
  // ---------------------------------------------------------------------------

  /**
   * Evaluate an incoming `X-InfraLayer-Owner-Override` header value.
   * A valid master signature applies the action; any other input returns
   * authorized:false and leaves the perimeter untouched (unprivileged traffic).
   */
  evaluateOverride(headerValue?: string | null, identity?: string | null): OwnerOverrideResult {
    const unauthorized = (reason: string, message: string): OwnerOverrideResult => ({
      authorized: false,
      action: null,
      applied: false,
      lockDown: this.lockDown,
      state: this.getState(),
      reason,
      message,
    });

    if (!headerValue) {
      return unauthorized('NO_OVERRIDE_HEADER', 'No owner-override header present; unprivileged traffic');
    }

    const parsed = this.parseOverride(headerValue);
    if (!parsed) {
      return unauthorized('MALFORMED_SIGNATURE', 'Malformed owner-override header; treated as unprivileged');
    }

    if (!this.masterKeyConfigured) {
      return unauthorized('MASTER_KEY_NOT_CONFIGURED', 'No master key configured; override ignored');
    }

    if (!this.verifySignature(parsed.signature)) {
      return unauthorized('INVALID_SIGNATURE', 'Owner signature mismatch; treated as unprivileged');
    }

    // Identity gate: the master key is bound to a sole named owner (default
    // "Evan Alvino"). A missing or mismatched identity claim is unprivileged
    // traffic — the override is NEVER applied.
    if (this.identityBound && !this.verifyIdentity(identity ?? null)) {
      return unauthorized(
        identity ? 'IDENTITY_MISMATCH' : 'IDENTITY_REQUIRED',
        identity
          ? 'Owner identity mismatch: override denied for unbound identity'
          : 'Owner identity claim missing; override denied'
      );
    }

    // Authorized path.
    this.lastOverrideAction = parsed.action;
    this.lastOverrideAt = new Date().toISOString();

    switch (parsed.action) {
      case 'LOCKDOWN':
        this.lockDown = true;
        return {
          authorized: true,
          action: 'LOCKDOWN',
          applied: true,
          lockDown: true,
          state: this.getState(),
          reason: 'OVERRIDE_APPLIED',
          message: 'System LOCKDOWN: fail-closed, 100% of context output dropped',
        };

      case 'THROTTLE': {
        const rps = this.parseRate(parsed.params[0]);
        if (rps === null || rps < 0) {
          return {
            authorized: true,
            action: 'THROTTLE',
            applied: false,
            lockDown: this.lockDown,
            state: this.getState(),
            reason: 'INVALID_THROTTLE_PARAM',
            message: 'THROTTLE ignored: invalid rate param',
          };
        }
        const clamped = Math.max(this.minConcurrency, Math.min(this.defaultMaxConcurrency, Math.floor(rps)));
        this.maxConcurrency = clamped;
        this.artificialLatencyMs = this.parseMs(parsed.params[1]);
        return {
          authorized: true,
          action: 'THROTTLE',
          applied: true,
          lockDown: this.lockDown,
          state: this.getState(),
          reason: 'OVERRIDE_APPLIED',
          message: `Throughput governor set to ${clamped} req/s (latency ${this.artificialLatencyMs}ms)`,
        };
      }

      case 'CACHE_PURGE': {
        const purged = this.purgeCaches();
        return {
          authorized: true,
          action: 'CACHE_PURGE',
          applied: true,
          lockDown: this.lockDown,
          state: this.getState(),
          reason: 'OVERRIDE_APPLIED',
          message: `Emergency cache purge: ${purged} resources evicted`,
        };
      }

      case 'RESET':
        this.reset();
        return {
          authorized: true,
          action: 'RESET',
          applied: true,
          lockDown: false,
          state: this.getState(),
          reason: 'OVERRIDE_APPLIED',
          message: 'Owner override state reset (lockdown lifted, throughput restored)',
        };

      default:
        return {
          authorized: true,
          action: parsed.action,
          applied: false,
          lockDown: this.lockDown,
          state: this.getState(),
          reason: 'UNKNOWN_ACTION',
          message: `Unknown owner action: ${parsed.action}`,
        };
    }
  }

  /** Split `<hexsig>:<ACTION>[:params...]` and validate the signature shape. */
  private parseOverride(headerValue: string): { signature: string; action: string; params: string[] } | null {
    const parts = headerValue.split(':');
    if (parts.length < 2) return null;
    const signature = parts[0];
    const action = parts[1].toUpperCase();
    const params = parts.slice(2);
    if (!/^[0-9a-f]{64}$/i.test(signature)) return null;
    return { signature, action, params };
  }

  /** Constant-time comparison of the presented signature against the stored hash. */
  private verifySignature(signature: string): boolean {
    if (!this.ownerKeyHash || signature.length !== this.ownerKeyHash.length) return false;
    const presented = Buffer.from(signature, 'hex');
    const expected = Buffer.from(this.ownerKeyHash, 'hex');
    return timingSafeEqual(presented, expected);
  }

  private parseRate(value: string | undefined): number | null {
    if (value === undefined) return null;
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }

  private parseMs(value: string | undefined): number {
    if (value === undefined) return 0;
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  // ---------------------------------------------------------------------------
  // Admission / throughput governor
  // ---------------------------------------------------------------------------

  /**
   * Admission gate run at the very top of sanitize(). While a LOCKDOWN is
   * engaged or the concurrency ceiling is saturated, admission is denied.
   * A granted admission must be paired with a later release().
   */
  admissionCheck(): OwnerAdmission {
    if (this.lockDown) {
      return {
        allowed: false,
        reason: 'SYSTEM_LOCKDOWN',
        throttled: false,
        maxConcurrency: this.maxConcurrency,
        activeConcurrency: this.activeConcurrency,
      };
    }
    if (this.activeConcurrency >= this.maxConcurrency) {
      return {
        allowed: false,
        reason: 'THROTTLE_CAPACITY_EXCEEDED',
        throttled: true,
        maxConcurrency: this.maxConcurrency,
        activeConcurrency: this.activeConcurrency,
      };
    }
    this.activeConcurrency++;
    this.lastAdmissionAt = Date.now();
    return {
      allowed: true,
      reason: 'ALLOWED',
      throttled: false,
      maxConcurrency: this.maxConcurrency,
      activeConcurrency: this.activeConcurrency,
    };
  }

  /** Release one admission slot (paired with a successful admissionCheck). */
  release(): void {
    if (this.activeConcurrency > 0) this.activeConcurrency--;
  }

  /** Programmatic throughput override (master channel not required). */
  setThrottle(rps: number): void {
    const clamped = Math.max(this.minConcurrency, Math.min(this.defaultMaxConcurrency, Math.floor(rps)));
    this.maxConcurrency = clamped;
  }

  /** Programmatic artificial-latency backpressure override. */
  setLatency(ms: number): void {
    this.artificialLatencyMs = Math.max(0, Math.floor(ms));
  }

  /**
   * Artificial latency backpressure for async callers. Sleeps the current
   * async frame for the configured latency window, then resolves.
   */
  async applyBackpressure(): Promise<void> {
    if (this.artificialLatencyMs > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, this.artificialLatencyMs));
    }
  }

  // ---------------------------------------------------------------------------
  // Emergency cache purge
  // ---------------------------------------------------------------------------

  /** Register an external purgeable resource so CACHE_PURGE evicts it too. */
  registerPurgeable(name: string, purge: () => number): void {
    this.purgeables.push({ name, purge });
  }

  /** Demonstration LRU token mapping (registration API for real caches). */
  registerLruToken(key: string, value: string, ttlMs = 60000): void {
    const now = Date.now();
    this.lruTokenMap.set(key, { value, expiresAt: now + ttlMs, lastAccess: now });
    this.touchLru();
  }

  /** Demonstration JWT revocation bitmask entry. */
  registerJwt(jwtId: string): void {
    this.jwtBitmask.add(jwtId);
  }

  /** Demonstration SharedArrayBuffer memory state. */
  registerSharedArrayBuffer(name: string, sizeBytes = 1024): void {
    this.sharedArrayBufferStates.set(name, new SharedArrayBuffer(sizeBytes));
  }

  /** Force-evict every registered in-memory cache + purgeable resource. */
  purgeCaches(): number {
    this.lruTokenMap.clear();
    this.jwtBitmask.clear();
    this.sharedArrayBufferStates.clear();
    let purged = 3;
    for (const resource of this.purgeables) {
      try {
        purged += resource.purge();
      } catch {
        // A failing external purge must never block the emergency path.
      }
    }
    this.lruPurgeCount++;
    this.jwtPurgeCount++;
    this.sabPurgeCount++;
    return purged;
  }

  private touchLru(): void {
    if (this.lruTokenMap.size > 1000) {
      // Bound the LRU: evict expired entries first, then the least-recently-used.
      const now = Date.now();
      for (const [key, entry] of this.lruTokenMap) {
        if (entry.expiresAt <= now) this.lruTokenMap.delete(key);
      }
      if (this.lruTokenMap.size > 1000) {
        let oldestKey: string | null = null;
        let oldestAccess = Infinity;
        for (const [key, entry] of this.lruTokenMap) {
          if (entry.lastAccess < oldestAccess) {
            oldestAccess = entry.lastAccess;
            oldestKey = key;
          }
        }
        if (oldestKey !== null) this.lruTokenMap.delete(oldestKey);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  /** Reset override state — lifts lockdown and restores full throughput. */
  reset(): void {
    this.lockDown = false;
    this.maxConcurrency = this.defaultMaxConcurrency;
    this.artificialLatencyMs = 0;
  }

  isLockedDown(): boolean {
    return this.lockDown;
  }

  getState(): OwnerControlState {
    return {
      lockDown: this.lockDown,
      maxConcurrency: this.maxConcurrency,
      activeConcurrency: this.activeConcurrency,
      artificialLatencyMs: this.artificialLatencyMs,
      defaultMaxConcurrency: this.defaultMaxConcurrency,
      minConcurrency: this.minConcurrency,
      lruPurgeCount: this.lruPurgeCount,
      jwtPurgeCount: this.jwtPurgeCount,
      sabPurgeCount: this.sabPurgeCount,
      lastOverrideAction: this.lastOverrideAction,
      lastOverrideAt: this.lastOverrideAt,
      masterKeyConfigured: this.masterKeyConfigured,
      ownerIdentity: this.ownerIdentity,
    };
  }

  /** Timestamp of the most recent admission (milliseconds since epoch). */
  get lastAdmissionTimestamp(): number {
    return this.lastAdmissionAt;
  }

  /** Current size of the internal LRU token map (observability/testing). */
  getLruCacheSize(): number {
    return this.lruTokenMap.size;
  }
}
