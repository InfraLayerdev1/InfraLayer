require("dotenv").config();
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY
);

const BASE_URL = process.env.PRODUCTION_URL || "https://gateway-alpha-gray.vercel.app";
const BYPASS_TOKEN = process.env.VERCEL_BYPASS_TOKEN || "";

const headers = {
  "Content-Type": "application/json",
  "x-vercel-protection-bypass": BYPASS_TOKEN
};

async function test() {
  // Check existing users in company-alpha
  const { data: memberships } = await sb
    .from("memberships")
    .select("*, users(*)")
    .eq("company_id", "d39d4b2a-3cb7-4d8c-b224-d6129752a65d");
  
  console.log("Memberships for company-alpha:", JSON.stringify(memberships, null, 2));

  // Try to login with one of these users
  if (memberships && memberships.length > 0) {
    const user = memberships[0].users;
    console.log("Trying to login as:", user.email);
    
    const login = await axios.post(`${BASE_URL}/auth/login`, {
      email: user.email,
      password: "TestPass123!"
    }, { headers, validateStatus: () => true });
    console.log("Login:", login.status, JSON.stringify(login.data, null, 2).substring(0, 500));

    if (login.data.token) {
      const ask = await axios.post(`${BASE_URL}/ask`, {
        question: "What is the PTO policy?",
        session_id: "test-session"
      }, {
        headers: { ...headers, Authorization: `Bearer ${login.data.token}` },
        validateStatus: () => true
      });
      console.log("Ask:", ask.status, JSON.stringify(ask.data, null, 2).substring(0, 800));
    }
  }
}

test();
