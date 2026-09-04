require("dotenv").config();
const axios = require("axios");
const jwt = require("jsonwebtoken");

const BASE_URL = process.env.PRODUCTION_URL || "https://gateway-alpha-gray.vercel.app";
const BYPASS_TOKEN = process.env.VERCEL_BYPASS_TOKEN || "2B92MQkTc1eZsD73N65ETypu7CZdW9k2";
const JWT_SECRET = process.env.JWT_SECRET || "d33305662eccbcbc270d5dd8cf131080cd126767fe27f5892613c370e6af322605cae045ec33d0a62fec1ea70f26b60f074dc5c55d1395e6bf71837e7c4b805c";

const headers = {
  "Content-Type": "application/json",
  "x-vercel-protection-bypass": BYPASS_TOKEN
};

// Use a known user from the database with company membership
// demo.executive@acme.com -> id: fa1b633e-af37-4efb-ad9c-6fe608288784, company: a1e63adc-7d21-4578-9784-790e2426375e
const userId = "fa1b633e-af37-4efb-ad9c-6fe608288784";
const token = jwt.sign({
  id: userId,
  email: "demo.executive@acme.com",
  company_id: "a1e63adc-7d21-4578-9784-790e2426375e",
  role: "admin",
  department: "Executive",
  access_level: "3"
}, JWT_SECRET, { expiresIn: "1h" });

console.log("Token:", token.substring(0, 50) + "...");

async function test() {
  const ask = await axios.post(`${BASE_URL}/ask`, {
    user_id: userId,
    session_id: "test-session",
    question: "What is the PTO policy?"
  }, {
    headers: { ...headers, Authorization: `Bearer ${token}` },
    validateStatus: () => true
  });
  console.log("Ask:", ask.status, JSON.stringify(ask.data, null, 2).substring(0, 800));
}

test();
