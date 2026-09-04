#!/usr/bin/env node
/**
 * Phase 10 · Block 2 — Turnkey Client Demo Suite & Enterprise Sandbox
 * ===================================================================
 * Idempotent demo-data seeder + automated clearance verification for the
 * multi-tenant RAG assistant:
 *
 *   1. get-or-create the demo company `demo-acme-corp` (companies.name)
 *   2. provision two demo accounts:
 *        demo.employee@acme.com  -> role user,  dept HR,        level 1
 *        demo.executive@acme.com -> role admin, dept Executive, level 3
 *      (each linked to the company via `memberships`)
 *   3. ingest 3 tiered knowledge bundles into `documents` + `document_chunks`
 *      with ownership metadata (company_id, department, min_access_level):
 *        A · HR        · level 1  "Acme Corp General Employee FAQ & Remote Work Policy"
 *        B · Sales     · level 2  "Acme Corp Q3 Regional Sales Strategy & Revenue Goals"
 *        C · Executive · level 3  "Confidential Executive Board Minutes & Acquisition Targets"
 *   4. automated clearance test (live retrieval RPC, mirroring the gateway):
 *        - demo.employee (level 1) querying the acquisition targets -> 0 chunks
 *        - demo.executive (level 3) querying the same -> Executive chunks retrieved
 *   5. clean execution telemetry
 *
 * SECURITY + DESIGN NOTES (verified live 2026-08-09):
 *  · Requires SUPABASE_SERVICE_ROLE_KEY (provisioning writes companies/memberships/
 *    documents, which are RLS-protected from the runtime anon key — same rule as
 *    scripts/create-tenant.js).
 *  · The retrieval RPC `match_document_chunks` filters `chunks.department =
 *    p_department OR chunks.department = 'ALL'`. An `ALL`-department user therefore
 *    sees ONLY `ALL`-tagged chunks — so the executive is department `'Executive'`
 *    (decision taken with the user) and sees the Executive-level bundle. Keep these
 *    tags consistent with the RPC semantics or the clearance test will fail.
 *  · Embeddings are synthetic one-hot 1536-dim vectors (one per bundle) so the seed
 *    needs no OPENAI_API_KEY, and the query vector (bundle C's signature) makes the
 *    similarity the *semantic* match while metadata does the *permission* filtering —
 *    exactly the pre-LLM security model the architecture enforces.
 *
 * Usage:
 *   npm run seed-demo
 *   npm run seed-demo -- --password "DemoPass!123"   # fixed demo password (turnkey)
 *   npm run seed-demo -- --company "other-name"      # override demo company name
 *   # Re-runnable: existing company/users/bundles are reused, never duplicated.
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
const EMBED_DIM = 1536;

if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error("\n⛔  MISSING ENVIRONMENT: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or legacy SUPABASE_KEY) are required.\n");
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ---- privileged-key guard (same rule as create-tenant.js) ----
function keyRole() {
    try {
        return JSON.parse(Buffer.from(SUPABASE_KEY.split(".")[1], "base64url").toString("utf8")).role || "unknown";
    } catch {
        return "unknown";
    }
}

// ============================================================
// DEMO SPEC
// ============================================================
const DEMO_COMPANY = { name: "demo-acme-corp" };

const DEMO_USERS = [
    { email: "demo.employee@acme.com",  full_name: "Demo Employee",  role: "user",  department: "HR",        level: "1" },
    { email: "demo.executive@acme.com", full_name: "Demo Executive", role: "admin", department: "Executive", level: "3" }
];

// Bundles: title / department / min_access_level / embedding signature index / chunk texts.
const DEMO_BUNDLES = [
    {
        title: "Acme Corp General Employee FAQ & Remote Work Policy",
        department: "HR",
        minAccessLevel: 1,
        signatureIndex: 0,
        chunks: [
            "Employees may work remotely up to three days per week. All remote work requests must be submitted through the HR portal at least 48 hours in advance.",
            "Full-time employees accrue 15 days of paid time off per year. Sick leave is separate and does not deduct from the PTO balance.",
            "The Acme Corp employee handbook is published on the intranet under Policies & Procedures. New hires must complete onboarding within 30 days of their start date."
        ]
    },
    {
        title: "Acme Corp Q3 Regional Sales Strategy & Revenue Goals",
        department: "Sales",
        minAccessLevel: 2,
        signatureIndex: 1,
        chunks: [
            "The Q3 revenue goal is $4.2M across the North American region, a 15% increase over Q2. Sales managers review the weekly pipeline on Fridays.",
            "Strategic focus for Q3: expand enterprise accounts in the healthcare vertical and refresh the mid-market outbound cadence.",
            "Regional directors hold a cross-region sync every Monday to flag at-risk deals and rebalance territories."
        ]
    },
    {
        title: "Confidential Executive Board Minutes & Acquisition Targets",
        department: "Executive",
        minAccessLevel: 3,
        signatureIndex: 2,
        chunks: [
            "The board approved a confidential acquisition budget of $120M for FY2026. The two priority targets are mid-size AI analytics firms codenamed Project Helios and Project Nova.",
            "Negotiations with Project Helios are targeted to close in Q4. The terms are highly confidential and must not be shared outside the executive team.",
            "Succession planning was discussed; a final decision is tabled until the January board meeting."
        ]
    }
];

/** One-hot signature vector for a bundle index — deterministic, no OpenAI key needed. */
function oneHotEmbedding(index, dim = EMBED_DIM) {
    const vec = new Array(dim).fill(0);
    vec[index] = 1;
    return vec;
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
    const args = { password: null, company: DEMO_COMPANY.name, help: false };
    for (let i = 0; i < argv.length; i++) {
        switch (argv[i]) {
            case "--password": args.password = argv[++i]; break;
            case "--company": case "-c": args.company = argv[++i]; break;
            case "--help": case "-h": args.help = true; break;
            default: if (argv[i].startsWith("--")) console.warn(`⚠️  Unknown flag ignored: ${argv[i]}`);
        }
    }
    return args;
}

function prompt(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); }));
}

/** 16-char password guaranteed to contain upper, lower, digit and symbol. */
function generateTempPassword(length = 16) {
    const classes = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "!@#$%^&*"];
    const all = classes.join("");
    const chars = classes.map((c) => c[crypto.randomInt(c.length)]);
    while (chars.length < length) chars.push(all[crypto.randomInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
}

/** Best-effort audit write — never throws, mirrors logAuditEvent semantics. */
async function writeAudit(details) {
    try {
        const { error } = await supabase.from("audit_logs").insert([{
            user_id: null,
            action: "DEMO_TENANT_SEEDED",
            details,
            ip_address: null,
            user_agent: "seed-demo-tenant-cli",
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
    console.error(`\n${red("⛔  SEED ABORTED")}: ${message}\n`);
    process.exit(1);
}

// ============================================================
// MAIN SEEDING + VERIFICATION FLOW
// ============================================================
async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
        console.log(`
${bold("seed-demo — Turnkey Client Demo Suite & Enterprise Sandbox")}

Usage:
  npm run seed-demo [--password "DemoPass!123"] [--company "demo-acme-corp"]

Options:
  --password <string>  Fixed password applied to BOTH demo accounts (turnkey demos).
                       Omitted -> a secure temporary password is generated per account.
  --company <string>   Demo company name (default "demo-acme-corp").
  --help               Show this help

What it does (idempotent — safe to re-run):
  · get-or-create company · 2 demo users + memberships · 3 tiered knowledge bundles
  · live clearance test: level-1 query -> 0 chunks; level-3 query -> Executive chunks
`);
        return;
    }

    if (keyRole() !== "service_role") {
        console.error(`\n⛔  SEEDING REQUIRES THE service_role KEY.`);
        console.error(`    Detected key role: "${keyRole()}"`);
        console.error(`    Add your Supabase service_role key to gateway/.env as SUPABASE_SERVICE_ROLE_KEY and re-run.\n`);
        process.exit(1);
    }

    const companyName = (args.company || DEMO_COMPANY.name).trim();
    const passwordOverride = args.password;

    let pass = 0, failCount = 0;
    const check = (label, ok, extra = "") => {
        console.log(`  ${ok ? green("✓") : red("✗")} ${label}${extra ? dim(" — " + extra) : ""}`);
        ok ? pass++ : failCount++;
    };

    console.log(`\n${bold("SEED DEMO TENANT")} — company: ${companyName}\n`);

    // ============================================================
    // STEP 1 — get-or-create company
    // ============================================================
    let { data: company } = await supabase.from("companies").select("id, name").eq("name", companyName).maybeSingle();
    if (!company) {
        const { data, error } = await supabase.from("companies").insert([{ name: companyName }]).select("id, name").single();
        if (error) return fail(`Failed to create company: ${error.message}`);
        company = data;
        console.log(`  ${green("✓")} company created — id ${company.id}`);
    } else {
        console.log(`  ${dim("→")} company already exists — reusing id ${company.id}`);
    }

    // ============================================================
    // STEP 2 — get-or-create demo users + memberships
    // ============================================================
    const provisioned = [];
    for (const u of DEMO_USERS) {
        const { data: existing } = await supabase.from("users").select("id, email, role").eq("email", u.email).maybeSingle();
        let user = existing;

        if (!user) {
            const password = passwordOverride || generateTempPassword();
            const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
            const { data, error } = await supabase
                .from("users")
                .insert([{ email: u.email, password_hash: hashed, full_name: u.full_name, role: u.role, status: "active" }])
                .select("id, email, role, status")
                .single();
            if (error) return fail(`Failed to create user ${u.email}: ${error.message}`);
            user = data;
            provisioned.push({ email: u.email, password });
        } else {
            provisioned.push({ email: u.email, password: null });
        }

        // membership: user -> company (department + level drive retrieval access)
        const { data: existingMem } = await supabase
            .from("memberships").select("id").eq("user_id", user.id).eq("company_id", company.id).maybeSingle();
        if (!existingMem) {
            const { error: mErr } = await supabase.from("memberships").insert([{
                user_id: user.id,
                company_id: company.id,
                role: u.role,
                department: u.department,
                level: u.level
            }]);
            if (mErr) return fail(`Failed to create membership for ${u.email}: ${mErr.message}`);
        }

        check(`user ${u.email}`, !!user, `id ${user.id} · role ${user.role}`);
        check(`  membership — dept ${u.department} · level ${u.level} (access_level ${u.level})`, true, `company ${company.id}`);
    }

    // ============================================================
    // STEP 3 — get-or-create tiered document bundles
    // ============================================================
    const bundleRows = {};
    for (const b of DEMO_BUNDLES) {
        const embedding = oneHotEmbedding(b.signatureIndex);
        const { data: existingDoc } = await supabase
            .from("documents").select("id").eq("company_id", company.id).eq("title", b.title).maybeSingle();

        if (existingDoc) {
            console.log(`  ${dim("→")} bundle already seeded — "${b.title}" (skip)`);
            bundleRows[b.signatureIndex] = existingDoc.id;
            continue;
        }

        // mirror ingestDocumentWithMetadata (gateway/server.js): documents row + chunk rows
        const { data: doc, error: docErr } = await supabase
            .from("documents")
            .insert([{
                company_id: company.id,
                title: b.title,
                department: b.department,
                content: b.chunks.join("\n")
            }])
            .select("id")
            .single();
        if (docErr) return fail(`Failed to create document "${b.title}": ${docErr.message}`);

        const rows = b.chunks.map((content) => ({
            document_id: doc.id,
            company_id: company.id,
            department: b.department,
            min_access_level: b.minAccessLevel,
            content,
            embedding
        }));
        const { error: cErr } = await supabase.from("document_chunks").insert(rows);
        if (cErr) return fail(`Failed to create chunks for "${b.title}": ${cErr.message}`);

        bundleRows[b.signatureIndex] = doc.id;
        console.log(`  ${green("✓")} ingested "${b.title}" — dept ${b.department} · min_access_level ${b.minAccessLevel} · ${rows.length} chunk(s)`);
    }

    // ============================================================
    // STEP 4 — automated clearance verification (live retrieval RPC)
    // ============================================================
    const queryEmbedding = oneHotEmbedding(2); // bundle C signature ("acquisition targets")
    const runQuery = async ({ department, accessLevel, label }) => {
        const { data, error } = await supabase.rpc("match_document_chunks", {
            query_embedding: queryEmbedding,
            match_threshold: 0.5,
            match_count: 5,
            p_company_id: company.id,
            p_department: department,
            p_access_level: accessLevel
        });
        if (error) return fail(`RAG retrieval failed for ${label}: ${error.message}`);
        return data || [];
    };

    console.log(`\n${bold("CLEARANCE VERIFICATION")} — query: "What are the secret acquisition targets?"\n`);

    const empChunks = await runQuery({ department: "HR", accessLevel: 1, label: "demo.employee" });
    check("demo.employee (level 1, HR) → 0 chunks (no leak)", empChunks.length === 0, `retrieved ${empChunks.length}`);

    const execChunks = await runQuery({ department: "Executive", accessLevel: 3, label: "demo.executive" });
    const allLevel3 = execChunks.every((c) => c.min_access_level === 3);
    const containsConfidential = execChunks.some((c) => /Helios|acquisition/i.test(c.content || ""));
    check("demo.executive (level 3, Executive) → Level 3 chunks retrieved", execChunks.length > 0, `retrieved ${execChunks.length}`);
    check("  all retrieved chunks are access_level 3", allLevel3, execChunks.length ? `levels: [${[...new Set(execChunks.map((c) => c.min_access_level))].join(",")}]` : "n/a");
    check("  retrieved chunks are the confidential bundle", containsConfidential, containsConfidential ? "Helios/acquisition content present" : "no match");

    // ============================================================
    // STEP 5 — audit + telemetry
    // ============================================================
    await writeAudit({
        company_id: company.id,
        company_name: companyName,
        users: DEMO_USERS.map((u) => ({ email: u.email, role: u.role, department: u.department, level: u.level })),
        bundles: DEMO_BUNDLES.map((b) => ({ title: b.title, department: b.department, min_access_level: b.minAccessLevel }))
    });

    console.log(`\n${pass && failCount === 0 ? green("✅  SEED + VERIFICATION COMPLETE") : red("❌  SEED + VERIFICATION FAILED")} — ${pass} passed, ${failCount} failed\n`);
    console.log(`${bold("DEMO LOGINS")}`);
    for (const p of provisioned) {
        console.log(`  ${p.email}`);
        console.log(`    password: ${p.password ? green(p.password) : dim("(existing account — password unchanged)")}`);
    }
    console.log(`\n${dim("→ Demo accounts are live. Log in via the gateway at the tenant above to try the sandbox.")}`);
    console.log(`${dim("→ Re-run safe: existing company/users/bundles are reused.")}\n`);

    process.exit(failCount ? 1 : 0);
}

main().catch((err) => {
    console.error(red("⛔  UNEXPECTED FAILURE:"), err.message);
    process.exit(1);
});
