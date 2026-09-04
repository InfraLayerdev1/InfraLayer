require("dotenv").config();
const axios = require("axios");

const BASE_URL = process.env.PRODUCTION_URL || "https://gateway-alpha-gray.vercel.app";
const BYPASS_TOKEN = process.env.VERCEL_BYPASS_TOKEN || "2B92MQkTc1eZsD73N65ETypu7CZdW9k2";

const headers = {
  "Content-Type": "application/json",
  "x-vercel-protection-bypass": BYPASS_TOKEN
};

async function test() {
  // Login as admin@alpha.com
  const login = await axios.post(`${BASE_URL}/auth/login`, {
    email: "admin@alpha.com",
    password: "TestPass123!"
  }, { headers, validateStatus: () => true });
  console.log("Login:", login.status, JSON.stringify(login.data, null, 2).substring(0, 500));

  if (login.data.token) {
    // Test /ask with valid token
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

test();
