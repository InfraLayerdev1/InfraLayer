require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY
);

async function check() {
  const { data: users, error: uErr } = await sb.from("users").select("*");
  console.log("Users:", uErr ? uErr.message : JSON.stringify(users, null, 2));

  const { data: companies, error: cErr } = await sb.from("companies").select("*");
  console.log("Companies:", cErr ? cErr.message : JSON.stringify(companies, null, 2));

  const { data: memberships, error: mErr } = await sb.from("memberships").select("*");
  console.log("Memberships:", mErr ? mErr.message : JSON.stringify(memberships, null, 2));
}

check();
