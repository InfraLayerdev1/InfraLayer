#!/usr/bin/env node
/**
 * @fileoverview System Owner Activation Switch — interactive console.
 *
 * This is the named-identity gate that gives the System Owner exclusive access
 * to the THREE override sequences built into the governance engine:
 *
 *   1. LOCKDOWN     — Global Circuit Breaker (kill-switch): fail-closed,
 *                     100% of context output dropped.
 *   2. THROTTLE     — Dynamic Throughput Governor: scale concurrency from
 *                     40,000 req/s down to 1 req/s, optional latency backpressure.
 *   3. CACHE_PURGE  — Emergency cache eviction: LRU token mappings, JWT
 *                     bitmasks, SharedArrayBuffers.
 *
 * Exercise flow:
 *   "Are you <owner name>? If yes, put the pass code below."
 *     -> pass code verified against INFRALAYER_OWNER_KEY_HASH (never stored plaintext)
 *     -> 3-sequence menu appears; pressing 1/2/3 runs EXACTLY that sequence.
 *
 * Any identity other than the bound name (default "Evan Alvino") is rejected.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const CORE_DIST = path.resolve(__dirname, '..', 'dist', 'index.js');
const ENV_FILE = process.argv.includes('--env-file')
  ? process.argv[process.argv.indexOf('--env-file') + 1]
  : path.resolve(__dirname, '..', '..', '..', '.env.local');

function loadEnv(file) {
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

function promptRaw(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
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
      resolve(answer.trim());
    });
  });
}

const SEQUENCES = [
  { key: '1', name: 'LOCKDOWN', description: 'Global Circuit Breaker · kill-switch · fail-closed · drop 100% of context output' },
  { key: '2', name: 'THROTTLE', description: 'Dynamic Throughput Governor · 40,000 → 1 req/s · optional latency backpressure' },
  { key: '3', name: 'CACHE_PURGE', description: 'Emergency Cache Eviction · LRU tokens · JWT bitmasks · SharedArrayBuffers' },
];

function renderMenu(state, maxConcurrency, showState) {
  const joined = SEQUENCES.map((s) => ` [${s.key}] ${s.name.padEnd(11)} ${s.description}`).join('\n');
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║        SYSTEM OWNER CONTROL — 3-SEQUENCE SWITCH              ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log(`\n${joined}`);
  if (showState) {
    console.log(
      `\n  Perimeter state:  lockDown=${state.lockDown}  concurrency=${state.maxConcurrency}/${maxConcurrency} req/s` +
        `  latency=${state.artificialLatencyMs}ms  purges=[LRU:${state.lruPurgeCount} JWT:${state.jwtPurgeCount} SAB:${state.sabPurgeCount}]`
    );
  }
  console.log('  [0] EXIT (release control)');
}

async function main() {
  const { SystemOwnerControl, InfraLayerCore, DEFAULT_MAX_CONCURRENCY } = require(CORE_DIST);

  const env = loadEnv(ENV_FILE);
  const hash = env.INFRALAYER_OWNER_KEY_HASH;
  const salt = env.INFRALAYER_OWNER_SALT;
  const ownerName = env.INFRALAYER_OWNER_NAME || 'Evan Alvino';

  if (!hash || !salt) {
    console.log(`\n⛔ No master key enrolled at ${ENV_FILE}.`);
    console.log('   Run: npm run owner-key  (packages/core) first.');
    process.exit(1);
  }

  const control = new SystemOwnerControl({ ownerKeyHash: hash, ownerSalt: salt, ownerIdentity: ownerName });

  // ---------------------------------------------------------------------------
  // Identity + pass code gate.
  console.log(`\n🔐 Are you ${ownerName}? If yes, put the pass code below.`);
  const passcode = await promptHidden('  pass code > ');

  // Signature probe with the sole-bound identity: authorized=true proves the
  // pass code AND the identity claim both check out.
  const probe = control.evaluateOverride(
    `${SystemOwnerControl.hashPassphrase(passcode, salt)}:PROBE`,
    ownerName
  );
  if (!probe.authorized) {
    console.log(`\n⛔ Access denied (${probe.reason}). This terminal is not bound to the system owner key.`);
    process.exit(1);
  }
  console.log(`\n✅ Identity confirmed: ${ownerName}. Master signature valid.`);

  // Attach the control to a core instance so sequence effects propagate to the
  // real sanitize() perimeter (Step 0) live.
  const core = new InfraLayerCore({ ownerControl: control });

  let running = true;
  while (running) {
    renderMenu(control.getState(), DEFAULT_MAX_CONCURRENCY, true);
    const choice = (await promptRaw('  select › ')).toLowerCase();

    if (choice === '0') {
      console.log('\n🛡️  Control released. Perimeter unchanged.');
      running = false;
      continue;
    }

    const seq = SEQUENCES.find((s) => s.key === choice);
    if (!seq) {
      console.log(`\n  Invalid choice: "${choice}". Press 1, 2, 3, or 0.`);
      continue;
    }

    if (seq.name === 'THROTTLE') {
      const rate = await promptRaw(`    req/s ceiling (1-${DEFAULT_MAX_CONCURRENCY}): `);
      const latency = await promptRaw('    artificial latency ms (0 = none): ');
      const res = control.evaluateOverride(
        SystemOwnerControl.signOverride(passcode, salt, 'THROTTLE', [rate || '1', latency || '0']),
        ownerName
      );
      console.log(`\n  ${res.applied ? '✅' : '⚠️'} [THROTTLE] ${res.message}`);
      if (res.applied) {
        const probe = core.sanitize({
          userContext: { userId: 'owner-console', tenantId: 'console-tenant', role: 'admin' },
          rawContext: { text: 'live throughput probe', metadata: { isGlobalPublic: true } },
        });
        console.log(`  sanitize() Step 0 verdict: "${probe.sanitizedContext?.text}"`);
      }
      continue;
    }

    const res = control.evaluateOverride(SystemOwnerControl.signOverride(passcode, salt, seq.name), ownerName);
    console.log(`\n  ${res.applied ? '✅' : '⚠️'} [${seq.name}] ${res.message}`);
    if (seq.name === 'CACHE_PURGE') {
      const st = control.getState();
      console.log(`  Purge ledger: LRU=${st.lruPurgeCount}  JWT=${st.jwtPurgeCount}  SharedArrayBuffer=${st.sabPurgeCount}`);
    }
  }
}

main().catch((err) => {
  console.error('Owner console error:', err);
  process.exit(1);
});