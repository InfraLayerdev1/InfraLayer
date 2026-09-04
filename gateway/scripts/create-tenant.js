#!/usr/bin/env node
/**
 * Phase 10 · Block 1 — Automated Tenant Provisioning
 * ===================================================
 * One-shot CLI that provisions a brand-new client tenant atomically:
 *
 *   1. Insert a row into `companies`  (live schema: id, name, created_at)
 *      -> the generated `companies.id` IS the tenant/company id
 *   2. Generate a secure temporary password
 *   3. Create the initial Super Admin in `users`
 *      (role: admin, status: active)
 *   4. Map the admin to the tenant via `memberships`
 *      (role: admin, department, level: "3"  => resolveAccessLevel -> 3)
 *   5. Audit `TENANT_PROVISIONED`
 *   6. Print a clean terminal summary with credentials
 *
 * SECURITY REQUIREMENT — service_role key:
 *   Provisioning writes to `companies` and `memberships`, which are RLS-guarded.
 *   The gateway's runtime key is `anon` and is *blocked* from those writes
 *   (verified live — this is the reason Phase 8 noted membership inserts were
 *   RLS-blocked). This tool therefore REQUIRES `SUPABASE_SERVICE_ROLE_KEY` in
 *   gateway/.env and refuses to run under a limited key.
 *
 * SCHEMA NOTE (verified live 2026-08-09):
 *   - `companies` = (id, name, created_at) — NOT the design-doc company_id/company_name
 *   - `users` has NO tenant columns; the user<->company mapping lives on `memberships`
 *   - `memberships.level` is free-form text; `"3"` parses to access_level 3 via
 *     resolveAccessLevel. Text labels ("Super Admin") would map to 1 — the most
 *     restrictive tier — and would silently cripple the tenant admin.
 *
 * Usage:
 *   npm run create-tenant -- --name "Company Name" --admin-email "admin@x.com" [--department "Executive"]
 *   node scripts/create-tenant.js --name "Company Name" --admin-email "admin@x.com" [--department "Executive"]
 *   # Omitting --name / --admin-email triggers interactive prompts.
 */

require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const readline = require("readline");

// ============================================================
// CONFIGURATION  (mirrors gateway/server.js env resolution)
// ============================================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const BCRYPT_ROUNDS = 10;

if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error("\n⛔  MISSING ENVIRONMENT: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or legacy SUPABASE_KEY) are required.");
    console.error("    Ensure gateway/.env is configured before provisioning.\n");
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ---- Privileged-key guard: provisioning needs service_role (companies/memberships are RLS-write-protected) ----
function keyRole() {
    try {
        return JSON.parse(Buffer.from(SUPABASE_KEY.split(".")[1], "base64url").toString("utf8")).role || "unknown";
    } catch {
        return "unknown";
    }
}

// ============================================================
// SMALL HELPERS
// ============================================================
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function parseArgs(argv) {
    const args = { name: null, adminEmail: null, department: "Executive", help: false };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        const val = () => argv[++i];
        switch (a) {
            case "--name": case "-n": args.name = val(); break;
            case "--admin-email": case "-e": args.adminEmail = val(); break;
            case "--department": case "-d": args.department = val(); break;
            case "--help": case "-h": args.help = true; break;
            default:
                if (a.startsWith("--")) {
                    console.warn(`⚠️  Unknown flag ignored: ${a}`);
                }
        }
    }
    return args;
}

function prompt(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); }));
}

function titleCase(s) {
    return s.replace(/\b\w/g, (c) => c.toUpperCase());
}

/** 16-char password guaranteed to contain upper, lower, digit and symbol. */
function generateTempPassword(length = 16) {
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const symbols = "!@#$%^&*";
    const classes = [upper, lower, digits, symbols];
    const all = upper + lower + digits + symbols;

    const chars = classes.map((c) => c[crypto.randomInt(c.length)]);
    while (chars.length < length) chars.push(all[crypto.randomInt(all.length)]);

    // Fisher–Yates shuffle so guaranteed chars aren't clustered at the front.
    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
}

/** Best-effort audit write — never throws, mirrors logAuditEvent semantics. */
async function writeAudit({ userId = null, action, details = {} }) {
    try {
        const { error } = await supabase
            .from("audit_logs")
            .insert([{
                user_id: userId,
                action,
                details,
                ip_address: null,
                user_agent: "create-tenant-cli",
                created_at: new Date().toISOString()
            }]);
        if (error) console.error(`⚠️  [AUDIT LOG ERROR]: ${error.message}`);
        return !error;
    } catch (err) {
        console.error(`⚠️  [AUDIT LOG CRITICAL EXCEPTION]: ${err.message}`);
        return false;
    }
}

async function fail(message) {
    console.error(`\n${red("⛔  PROVISIONING ABORTED")}: ${message}\n`);
    process.exit(1);
}

// ============================================================
// MAIN PROVISIONING FLOW
// ============================================================
async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
        console.log(`
${bold("create-tenant — Automated Tenant Provisioning")}

Usage:
  npm run create-tenant -- --name "Company Name" --admin-email "admin@x.com" [--department "Executive"]

Options:
  --name <string>        Company / tenant name            (required, or prompted)
  --admin-email <email>  Super-admin account email        (required, or prompted)
  --department <string>  Department for the admin role    (default: "Executive")
  --help                 Show this help

Notes:
  · Requires SUPABASE_SERVICE_ROLE_KEY in gateway/.env (privileged provisioning).
  · Creates companies -> users(admin) -> memberships(level 3) -> audit(TENANT_PROVISIONED).
  · A secure temporary password is generated and printed once. Rotate on first login.
`);
        return;
    }

    // ---- privileged-key guard (after help, so --help always works) ----
    if (keyRole() !== "service_role") {
        console.error(`\n⛔  PROVISIONING REQUIRES THE service_role KEY.`);
        console.error(`    Detected key role: "${keyRole()}"`);
        console.error(`    The gateway's runtime key (anon) is RLS-blocked from writing to \`companies\` and \`memberships\` (verified live).`);
        console.error(`    Add your Supabase service_role key to gateway/.env as SUPABASE_SERVICE_ROLE_KEY and re-run.\n`);
        process.exit(1);
    }

    // ---- resolve inputs (CLI flag or interactive prompt) ----
    let { name, adminEmail, department } = args;
    if (!name) name = await prompt(`Company name: `);
    if (!adminEmail) adminEmail = await prompt(`Admin email: `);
    if (!args.department) department = (await prompt(`Department [${department}]: `)) || department;

    name = (name || "").trim();
    adminEmail = (adminEmail || "").trim().toLowerCase();
    department = (department || "").trim();

    if (!name) return fail("Company name is required.");
    if (!EMAIL_RE.test(adminEmail)) return fail(`Invalid admin email: "${adminEmail}".`);
    if (!department) return fail("Department is required.");

    // ---- pre-flight duplicate guards ----
    const { data: existingCompany } = await supabase
        .from("companies").select("id").eq("name", name).maybeSingle();
    if (existingCompany) {
        return fail(`A company named "${name}" already exists (id: ${existingCompany.id}). Provisioning aborted — no data written.`);
    }
    const { data: existingUser } = await supabase
        .from("users").select("id").eq("email", adminEmail).maybeSingle();
    if (existingUser) {
        return fail(`An account with email "${adminEmail}" already exists (id: ${existingUser.id}). Provisioning aborted — no data written.`);
    }

    // ---- step 1: insert company -> tenant id ----
    const { data: company, error: companyErr } = await supabase
        .from("companies")
        .insert([{ name }])
        .select("id, name, created_at")
        .single();

    if (companyErr || !company) {
        return fail(`Failed to create company row: ${companyErr?.message || "no row returned"}`);
    }
    const companyId = company.id;

    try {
        // ---- step 2 & 3: generate temp password + create super admin ----
        const tempPassword = generateTempPassword();
        const hashedPassword = await bcrypt.hash(tempPassword, BCRYPT_ROUNDS);

        const { data: adminUser, error: userErr } = await supabase
            .from("users")
            .insert([{
                email: adminEmail,
                password_hash: hashedPassword,
                full_name: titleCase(adminEmail.split("@")[0]),
                role: "admin",
                status: "active"
            }])
            .select("id, email, full_name, role, status")
            .single();

        if (userErr || !adminUser) {
            throw new Error(`Failed to create admin user: ${userErr?.message || "no row returned"}`);
        }

        // ---- step 4: map admin to tenant (level "3" => access_level 3) ----
        const { error: membershipErr } = await supabase
            .from("memberships")
            .insert([{
                user_id: adminUser.id,
                company_id: companyId,
                role: "admin",
                department,
                level: "3"
            }]);

        if (membershipErr) {
            throw new Error(`Failed to create membership: ${membershipErr.message}`);
        }

        // ---- step 5: audit ----
        await writeAudit({
            userId: adminUser.id,
            action: "TENANT_PROVISIONED",
            details: {
                company_id: companyId,
                company_name: name,
                admin_email: adminEmail,
                department,
                access_level: 3
            }
        });

        // ---- step 6: summary ----
        console.log(`\n${green("✅  TENANT PROVISIONED SUCCESSFULLY")}\n`);
        console.log(`${bold("COMPANY")}`);
        console.log(`  Name            : ${name}`);
        console.log(`  Company ID      : ${companyId}`);
        console.log(``);
        console.log(`${bold("SUPER ADMIN")}`);
        console.log(`  Email           : ${adminEmail}`);
        console.log(`  Department      : ${department}`);
        console.log(`  Role            : admin`);
        console.log(`  Access Level    : 3 (via memberships.level = "3")`);
        console.log(``);
        console.log(`${bold("TEMPORARY PASSWORD")}`);
        console.log(`  ${green(tempPassword)}`);
        console.log(``);
        console.log(`${dim("→ Rotate this password on first login. It will not be shown again.")}`);
        console.log(`${dim("→ Audit entry written: TENANT_PROVISIONED (user_id " + adminUser.id + ").")}\n`);
    } catch (err) {
        // ---- rollback (best-effort, reverse order) so nothing is half-written ----
        console.error(`${red("⛔  PROVISIONING FAILED")}: ${err.message}`);
        console.error(dim("Rolling back partial writes…"));
        const { error: delUserErr } = await supabase.from("users").delete().eq("email", adminEmail);
        const { error: delCompanyErr } = await supabase.from("companies").delete().eq("id", companyId);
        if (delUserErr || delCompanyErr) {
            console.error(dim(`⚠️  Rollback incomplete — user: ${delUserErr?.message || "ok"}, company: ${delCompanyErr?.message || "ok"}`));
            process.exit(1);
        }
        console.error(dim("Rollback complete — no data written."));
        process.exit(1);
    }
}

main().catch((err) => {
    console.error(red("⛔  UNEXPECTED FAILURE:"), err.message);
    process.exit(1);
});
