#!/usr/bin/env node
/**
 * @fileoverview Targeted verification for the SystemOwnerControl engine.
 *
 * Proves two invariants against the BUILT package:
 *   1. A valid Master Key signature grants instant override authority
 *      (LOCKDOWN kill-switch trips and 100% of context output is dropped).
 *   2. An invalid signature is treated as STANDARD UNPRIVILEGED traffic
 *      (sanitize proceeds untouched, no lockdown, no state change).
 *
 * Key source: INFRALAYER_OWNER_MASTER_KEY env var, or --passphrase, or an
 * interactive prompt. Hash/salt read from .env.local:
 *   INFRALAYER_OWNER_KEY_HASH / INFRALAYER_OWNER_SALT.
 */

'use strict';

const path = require('node:path');
const readline = require('node:readline');

const CORE_DIST = path.resolve(__dirname, '..', 'dist', 'index.js');
const ENV_FILE = process.argv.includes('--env-file')
  ? process.argv[process.argv.indexOf('--env-file') + 1]
  : path.resolve(__dirname, '..', '..', '..', '.env.local');

function loadEnv(file) {
  const fs = require('node:fs');
  const out = {};
  try {
    const content = fs.readFileSync(file, 'utf8');
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      let key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      out[key] = val;
    }
  } catch {
    /* absent file handled by caller */
  }
  return out;
}

function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = function (stringToWrite) {
      if (stringToWrite.includes(query)) rl.output.write(stringToWrite);
      else rl.output.write('*');
    };
    rl.question(query, (answer) => {
      rl.output.write('\n');
      rl.close();
      resolve(answer);
    });
  });
}

let PASS = 0;
let FAIL = 0;
function check(name, cond, detail = '') {
  if (cond) {
    PASS++;
    console.log(`  ✅ PASS ${name}${detail ? ` — ${detail}` : ''}`);
  } else {
    FAIL++;
    console.log(`  ❌ FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function main() {
  const { SystemOwnerControl, InfraLayerCore } = require(CORE_DIST);
  const env = loadEnv(ENV_FILE);
  const hash = env.INFRALAYER_OWNER_KEY_HASH;
  const salt = env.INFRALAYER_OWNER_SALT;
  const ownerName = env.INFRALAYER_OWNER_NAME || 'Evan Alvino';

  let passphrase =
    process.env.INFRALAYER_OWNER_MASTER_KEY ||
    (process.argv.includes('--passphrase')
      ? process.argv[process.argv.indexOf('--passphrase') + 1]
      : null);

  if (!passphrase) {
    console.log('\n🔐  ENTER SYSTEM OWNER MASTER KEY / PASSPHRASE: ');
    passphrase = await promptHidden('> ');
  }

  console.log('\n=== SystemOwnerControl Verification ===');
  if (!hash) {
    console.log(`\n⛔ No INFRALAYER_OWNER_KEY_HASH in ${ENV_FILE}.`);
    console.log('   Run: npm run owner-key  (packages/core) first.');
    process.exit(1);
  }
  console.log(`   Master key configured: yes (${hash.slice(0, 12)}…, salt ${salt.length} hex chars)`);
  console.log(`   Master key bound to  : ${ownerName} (sole owner identity)`);

  const control = new SystemOwnerControl({ ownerKeyHash: hash, ownerSalt: salt, ownerIdentity: ownerName });
  const core = new InfraLayerCore({ ownerControl: control });
  const user = { userId: 'verify-user', tenantId: 'verify-tenant', role: 'admin', accessLevel: 5 };
  const payload = 'TOP SECRET context that must never reach the LLM';

  // -------------------------------------------------------------------------
  console.log('\n[1] Global Circuit Breaker (LOCKDOWN) — valid signature');
  const validLockdown = SystemOwnerControl.signOverride(passphrase, salt, 'LOCKDOWN');
  const tripped = control.evaluateOverride(validLockdown, ownerName);
  check('valid signature tripped the kill-switch', tripped.authorized === true && tripped.lockDown === true);
  check('core sanitize dropped 100% of context output', (() => {
    const r = core.sanitize({ userContext: user, ownerOverride: validLockdown, ownerOverrideIdentity: ownerName, rawContext: { text: payload, metadata: { isGlobalPublic: true } } });
    return r.sanitizedContext?.text.includes('LOCKDOWN') && !r.sanitizedContext?.text.includes('TOP SECRET') && r.sanitizedContext?.sanitizedLength === 0;
  })());

  // recovery for the rest of the battery
  control.evaluateOverride(SystemOwnerControl.signOverride(passphrase, salt, 'RESET'), ownerName);
  check('valid RESET lifted the lockdown', control.isLockedDown() === false);

  // -------------------------------------------------------------------------
  console.log('\n[2] Invalid signature = standard unprivileged traffic');
  const forged = `${'a'.repeat(64)}:LOCKDOWN`;
  const rejected = control.evaluateOverride(forged, ownerName);
  check('forged signature is unauthorized', rejected.authorized === false && rejected.lockDown === false);
  check('core sanitize proceeded untouched under a forged header', (() => {
    const r = core.sanitize({ userContext: user, ownerOverride: forged, ownerOverrideIdentity: ownerName, rawContext: { text: payload, metadata: { isGlobalPublic: true } } });
    return r.sanitizedContext?.text.includes('TOP SECRET') && !r.sanitizedContext?.securityFlags.some((f) => f.flag === 'SYSTEM_LOCKDOWN');
  })());
  check('no governor state mutated by the forgery', control.getState().maxConcurrency === 40000 && !control.isLockedDown());

  // -------------------------------------------------------------------------
  console.log('\n[3] Owner-Identity Gate (bound to one name only)');
  const wrongIdentity = control.evaluateOverride(validLockdown, 'Someone Else');
  check('valid signature + WRONG identity is rejected', wrongIdentity.authorized === false && wrongIdentity.reason === 'IDENTITY_MISMATCH' && wrongIdentity.lockDown === false);
  const missingIdentity = control.evaluateOverride(validLockdown, null);
  check('valid signature + missing identity is rejected', missingIdentity.authorized === false && missingIdentity.reason === 'IDENTITY_REQUIRED' && missingIdentity.lockDown === false);
  check('valid signature + correct identity applies the override', (() => {
    const applied = control.evaluateOverride(SystemOwnerControl.signOverride(passphrase, salt, 'CACHE_PURGE'), ownerName);
    return applied.authorized === true && applied.applied === true;
  })());

  // -------------------------------------------------------------------------
  console.log('\n[4] Dynamic Throughput Governor (THROTTLE) — valid signature');
  const throttled = control.evaluateOverride(SystemOwnerControl.signOverride(passphrase, salt, 'THROTTLE', ['1', '0']), ownerName);
  check('governor scaled 40000 -> 1 req/s', throttled.applied === true && control.getState().maxConcurrency === 1);
  control.admissionCheck();
  const saturated = core.sanitize({ userContext: user, rawContext: { text: payload, metadata: { isGlobalPublic: true } } });
  check('saturated capacity returned a throttled zero-output marker', saturated.sanitizedContext?.text.includes('capacity') && saturated.sanitizedContext?.sanitizedLength === 0 && saturated.sanitizedContext?.securityFlags.some((f) => f.flag === 'SYSTEM_THROTTLED'));
  control.release();
  control.evaluateOverride(SystemOwnerControl.signOverride(passphrase, salt, 'RESET'), ownerName);

  // -------------------------------------------------------------------------
  console.log('\n[5] Emergency Cache Purge (CACHE_PURGE) — valid signature');
  control.registerLruToken('verify-tok', 'v');
  control.registerJwt('verify-jwt');
  control.registerSharedArrayBuffer('verify-sbuf');
  const purged = control.evaluateOverride(SystemOwnerControl.signOverride(passphrase, salt, 'CACHE_PURGE'), ownerName);
  const st = control.getState();
  check('purge applied and counters incremented', purged.applied === true && st.lruPurgeCount >= 1 && st.jwtPurgeCount >= 1 && st.sabPurgeCount >= 1);

  // -------------------------------------------------------------------------
  console.log('\n════════════ SUMMARY ════════════');
  console.log(`  Valid master signature grants override authority   ✅ / Invalid treated unprivileged  ✅`);
  if (FAIL === 0) {
    console.log(`  RESULT: ALL ${PASS} CHECKS PASS — SystemOwnerControl verified live.`);
  } else {
    console.log(`  RESULT: ${FAIL} of ${PASS + FAIL} checks FAILED.`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('Verification error:', err);
  process.exit(1);
});