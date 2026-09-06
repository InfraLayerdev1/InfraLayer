#!/usr/bin/env node
/**
 * @fileoverview Interactive System Owner Master Key Acquisition.
 *
 * PAUSES execution and prompts the System Owner for the master passphrase,
 * hashes it with SHA-256 + a fresh random per-install salt, and writes
 * INFRALAYER_OWNER_KEY_HASH / INFRALAYER_OWNER_SALT to `.env.local`
 * (gitignored — the plaintext passphrase is never persisted).
 *
 * Non-interactive: pass --passphrase <key> or INFRALAYER_OWNER_MASTER_KEY env.
 * Override target file: --env-file <path>.
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const DEFAULT_ENV_FILE = path.resolve(__dirname, '..', '..', '..', '.env.local');
const DEFAULT_OWNER_NAME = 'Evan Alvino';
const MIN_PASSPHRASE_LENGTH = 12;

function parseArgs(argv) {
  const args = { passphrase: null, ownerName: DEFAULT_OWNER_NAME, envFile: DEFAULT_ENV_FILE };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--passphrase') args.passphrase = argv[++i] ?? null;
    else if (argv[i] === '--owner-name') args.ownerName = argv[++i] ?? DEFAULT_OWNER_NAME;
    else if (argv[i] === '--env-file') args.envFile = argv[++i] ?? DEFAULT_ENV_FILE;
    else if (argv[i] === '--help' || argv[i] === '-h') args.help = true;
  }
  return args;
}

function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });
    // Mask every keystroke after the query line.
    rl._writeToOutput = function (stringToWrite) {
      if (stringToWrite.includes(query)) {
        rl.output.write(stringToWrite);
      } else {
        rl.output.write('*');
      }
    };
    rl.question(query, (answer) => {
      rl.output.write('\n');
      rl.close();
      resolve(answer);
    });
  });
}

function readExistingEnv(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

/**
 * Insert or update a KEY=VALUE pair while preserving all other lines and
 * any existing INFRALAYER_OWNER_* values are replaced in place.
 */
function upsertEnv(content, key, value) {
  const lines = content.split(/\r?\n/);
  let replaced = false;
  const out = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return line;
    const eq = trimmed.indexOf('=');
    if (eq === -1) return line;
    if (trimmed.slice(0, eq).trim() === key) {
      replaced = true;
      return `${key}=${value}`;
    }
    return line;
  });
  if (!replaced) out.push(`${key}=${value}`);
  return out.join('\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    console.log(
      [
        'System Owner Master Key Acquisition',
        '',
        'Usage: node scripts/acquire-owner-key.js [--passphrase <key>] [--owner-name <name>] [--env-file <path>]',
        '',
        '  --passphrase   Supply the master passphrase non-interactively',
        '                 (or set INFRALAYER_OWNER_MASTER_KEY). Omitted -> prompt.',
        '  --owner-name   The sole named identity bound to this master key.',
        '                 (default: "Evan Alvino")',
        '  --env-file     Target .env.local (default: company-ai/.env.local)',
        '',
      ].join('\n')
    );
    process.exit(0);
  }

  let passphrase = args.passphrase || process.env.INFRALAYER_OWNER_MASTER_KEY || null;

  if (!passphrase) {
    console.log('\n🔐  ENTER SYSTEM OWNER MASTER KEY / PASSPHRASE: ');
    passphrase = await promptHidden('> ');
  }

  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    console.error(`\n⛔ Master passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters. Aborting.`);
    process.exit(1);
  }

  // Fresh random per-install salt — same passphrase yields a different hash on
  // every install, so a leaked hash from one environment is unusable elsewhere.
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .createHash('sha256')
    .update(salt)
    .update(':')
    .update(passphrase)
    .digest('hex');

  let content = readExistingEnv(args.envFile);
  content = upsertEnv(content, 'INFRALAYER_OWNER_KEY_HASH', hash);
  content = upsertEnv(content, 'INFRALAYER_OWNER_SALT', salt);
  content = upsertEnv(content, 'INFRALAYER_OWNER_NAME', args.ownerName);
  fs.writeFileSync(args.envFile, content.trimEnd() + '\n', 'utf8');

  console.log('\n✅ Master key enrolled.');
  console.log(`   Bound to  : ${args.ownerName} (sole owner identity)`);
  console.log(`   Wrote to : ${args.envFile}`);
  console.log(`   Hash     : ${hash}`);
  console.log(`   Salt     : ${salt}`);
  console.log('   The plaintext passphrase was NEVER persisted. Guard it out-of-band.');
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
