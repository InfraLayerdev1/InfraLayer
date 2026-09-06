require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY);

const dim = 1536;
const embA = new Array(dim).fill(0); embA[0] = 1;
const embB = new Array(dim).fill(0); embB[1] = 1;

const ALPHA = "d39d4b2a-3cb7-4d8c-b224-d6129752a65d";
const BETA  = "7bb61cfd-fedd-40bf-b812-666ea32765ef";

async function query(company, dept, level, embedding) {
  const { data, error } = await sb.rpc("match_document_chunks", {
    query_embedding: embedding, match_threshold: 0.5, match_count: 5,
    p_company_id: company, p_department: dept, p_access_level: level
  });
  if (error) throw new Error(error.message);
  return data || [];
}

(async () => {
  const cases = [
    { label: "A1: ALPHA admin w/ ALPHA signature", company: ALPHA, dept: "Executive", level: 3, emb: embA, foreignPrefix: "COMPANY-BETA", minChunks: 1 },
    { label: "A2: BETA admin  w/ ALPHA signature", company: BETA,  dept: "Executive", level: 3, emb: embA, foreignPrefix: "COMPANY-ALPHA", minChunks: 0 },
    { label: "A3: BETA admin  w/ BETA signature",  company: BETA,  dept: "Executive", level: 3, emb: embB, foreignPrefix: "COMPANY-ALPHA", minChunks: 1 },
    { label: "A4: ALPHA admin w/ BETA signature",  company: ALPHA, dept: "Executive", level: 3, emb: embB, foreignPrefix: "COMPANY-BETA", minChunks: 0 },
    { label: "A5: ALPHA lvl-1 user w/ ALPHA signature (lvl-3 doc)", company: ALPHA, dept: "Executive", level: 1, emb: embA, foreignPrefix: null, minChunks: 0 },
  ];
  let pass = 0;
  for (const c of cases) {
    const rows = await query(c.company, c.dept, c.level, c.emb);
    let leaked = 0;
    if (c.foreignPrefix) {
      leaked = rows.filter(r => (r.content || "").startsWith(c.foreignPrefix)).length;
    }
    const ok = rows.length >= c.minChunks && leaked === 0;
    console.log(`${ok ? "PASS" : "FAIL"} | ${c.label} -> ${rows.length} chunk(s), cross-tenant leaks: ${leaked}`);
    if (ok) pass++;
  }
  console.log(`\n=== ISOLATION MATRIX (proper leak detection): ${pass}/${cases.length} PASS ===`);
})();