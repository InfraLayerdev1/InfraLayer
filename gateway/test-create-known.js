require("dotenv").config();
const axios = require("axios");
const bcrypt = require("bcrypt");

const BASE_URL = process.env.PRODUCTION_URL || "https://gateway-alpha-gray.vercel.app";
const BYPASS_TOKEN = process.env.VERCEL_BYPASS_TOKEN || "2B92MQkTc1eZsD73N65ETypu7CZdW9k2";

const headers = {
  "Content-Type": "application/json",
  "x-vercel-protection-bypass": BYPASS_TOKEN
};

async function test() {
  const email = `test-pen-${Date.now()}@example.com`;
  const password = "KnownPass123!";
  
  // Signup
  const signup = await axios.post(`${BASE_URL}/auth/signup`, {
    email,
    password,
    full_name: "Pen Test User",
    company_name: "Pen Test Company"
  }, { headers, validateStatus: () => true });
  console.log("Signup:", signup.status, JSON.stringify(signup.data, null, 2).substring(0, 500));

  if (signup.data.token) {
    // Test /ask with valid token
    const ask = await axios.post(`${BASE_URL}/ask`, {
      question: "What is the PTO policy?",
      session_id: "test-session"
    }, {
      headers: { ...headers, Authorization: `Bearer ${signup.data.token}` },
      validateStatus: () => true
    });
    console.log("Ask:", ask.status, JSON.stringify(ask.data, null, 2).substring(0, 800));
  }
}

test();
