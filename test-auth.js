require("dotenv").config();
const axios = require("axios");

const BASE_URL = process.env.PRODUCTION_URL || "https://gateway-alpha-gray.vercel.app";
const BYPASS_TOKEN = process.env.VERCEL_BYPASS_TOKEN || "";

const headers = {
  "Content-Type": "application/json",
  "x-vercel-protection-bypass": BYPASS_TOKEN
};

async function testAuth() {
  // Try to signup a test user
  try {
    const signup = await axios.post(`${BASE_URL}/auth/signup`, {
      email: `test-${Date.now()}@example.com`,
      password: "TestPass123!",
      full_name: "Test User",
      company_name: "Test Company"
    }, { headers, validateStatus: () => true });
    console.log("Signup:", signup.status, signup.data);

    if (signup.data.token) {
      // Test /ask with valid token
      const ask = await axios.post(`${BASE_URL}/ask`, {
        question: "What is the PTO policy?"
      }, {
        headers: { ...headers, Authorization: `Bearer ${signup.data.token}` },
        validateStatus: () => true
      });
      console.log("Ask:", ask.status, ask.data);
    }
  } catch (e) {
    console.log("Error:", e.message);
  }
}

testAuth();
