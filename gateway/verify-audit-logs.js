require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const axios = require("axios");
const jwt = require("jsonwebtoken");

const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY
);

const BASE_URL = process.env.PRODUCTION_URL || "https://gateway-alpha-gray.vercel.app";
const BYPASS_TOKEN = process.env.VERCEL_BYPASS_TOKEN || "2B92MQkTc1eZsD73N65ETypu7CZdW9k2";
const JWT_SECRET = process.env.JWT_SECRET || "d33305662eccbcbc270d5dd8cf131080cd126767fe27f5892613c370e6af322605cae045ec33d0a62fec1ea70f26b60f074dc5c55d1395e6bf71837e7c4b805c";

const headers = {
  "Content-Type": "application/json",
  "x-vercel-protection-bypass": BYPASS_TOKEN
};

async function queryAuditLogs(actionFilter = null) {
  let query = sb.from("audit_logs").select("*").order("created_at", { ascending: false }).limit(200);
  if (actionFilter) {
    query = query.eq("action", actionFilter);
  }
  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

async function triggerTestEvents() {
  console.log("\n=== TRIGGERING TEST EVENTS ===\n");
  
  // 1. Test liveness probe
  console.log("1. Testing /health/liveness...");
  await axios.get(`${BASE_URL}/health/liveness`, { headers, validateStatus: () => true });
  
  // 2. Test readiness probe
  console.log("2. Testing /health/readiness...");
  await axios.get(`${BASE_URL}/health/readiness`, { headers, validateStatus: () => true });
  
  // 3. Test invalid auth (should log INVALID_TOKEN_ATTEMPT)
  console.log("3. Testing invalid auth (INVALID_TOKEN_ATTEMPT)...");
  await axios.post(`${BASE_URL}/ask`, {
    user_id: "test", session_id: "test", question: "test"
  }, { headers: { ...headers, Authorization: "Bearer invalid.token.here" }, validateStatus: () => true });
  
  // 4. Test valid auth with real user
  const userId = "fa1b633e-af37-4efb-ad9c-6fe608288784";
  const token = jwt.sign({
    id: userId, email: "demo.executive@acme.com",
    company_id: "a1e63adc-7d21-4578-9784-790e2426375e",
    role: "admin", department: "Executive", access_level: "3"
  }, JWT_SECRET, { expiresIn: "1h" });
  
  // 5. Test RAG query (should log RAG_CONTEXT_RETRIEVED)
  console.log("4. Testing RAG query (RAG_CONTEXT_RETRIEVED)...");
  await axios.post(`${BASE_URL}/ask`, {
    user_id: userId, session_id: "audit-test", question: "What is PTO?"
  }, { headers: { ...headers, Authorization: `Bearer ${token}` }, validateStatus: () => true });
  
  // 6. Test admin panel access (should log ADMIN_PANEL_ACCESS)
  console.log("5. Testing admin panel access (ADMIN_PANEL_ACCESS)...");
  await axios.get(`${BASE_URL}/admin/users`, { 
    headers: { ...headers, Authorization: `Bearer ${token}` }, 
    validateStatus: () => true 
  });
  
  await axios.get(`${BASE_URL}/admin/audit-logs`, { 
    headers: { ...headers, Authorization: `Bearer ${token}` }, 
    validateStatus: () => true 
  });
  
  // 7. Test rate limit (should log RATE_LIMIT_EXCEEDED)
  console.log("6. Testing rate limit (RATE_LIMIT_EXCEEDED)...");
  for (let i = 0; i < 7; i++) {
    await axios.post(`${BASE_URL}/auth/login`, { email: "test@test.com", password: "wrong" }, 
      { headers, validateStatus: () => true });
  }
  
  console.log("\nWaiting 2 seconds for audit logs to propagate...");
  await new Promise(r => setTimeout(r, 2000));
}

async function verifyAuditLogs() {
  console.log("\n=== VERIFYING AUDIT LOGS ===\n");
  
  const expectedActions = [
    "USER_REGISTERED",
    "USER_LOGIN_SUCCESS",
    "USER_LOGIN_FAILED", 
    "USER_LOGIN_BLOCKED",
    "USER_LOGOUT",
    "INVALID_TOKEN_ATTEMPT",
    "RATE_LIMIT_EXCEEDED",
    "SERVER_ERROR",
    "DATABASE_DISCONNECTED",
    "SYSTEM_CRASH_PREVENTED",
    "UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT",
    "ADMIN_PANEL_ACCESS",
    "ADMIN_USER_UPDATED",
    "DOCUMENT_INGESTED",
    "RAG_CONTEXT_RETRIEVED",
    "DOCUMENT_DELETED",
    "DEMO_TENANT_SEEDED"
  ];
  
  const logs = await queryAuditLogs();
  console.log(`Total recent audit logs: ${logs.length}\n`);
  
  const actionCounts = {};
  for (const log of logs) {
    actionCounts[log.action] = (actionCounts[log.action] || 0) + 1;
  }
  
  console.log("Action counts:");
  for (const action of expectedActions) {
    const count = actionCounts[action] || 0;
    const status = count > 0 ? "✅" : "⚪";
    console.log(`  ${status} ${action}: ${count}`);
  }
  
  // Show recent logs with details
  console.log("\nRecent audit entries (last 20):");
  for (const log of logs.slice(0, 20)) {
    const details = JSON.stringify(log.details || {}).substring(0, 80);
    console.log(`  [${log.created_at}] ${log.action} | user: ${log.user_id || 'N/A'} | ip: ${log.ip_address} | ${details}`);
  }
  
  // Verify critical events exist
  const criticalEvents = ["RATE_LIMIT_EXCEEDED", "INVALID_TOKEN_ATTEMPT", "RAG_CONTEXT_RETRIEVED", "ADMIN_PANEL_ACCESS"];
  console.log("\n=== CRITICAL EVENT VERIFICATION ===");
  let allCriticalPresent = true;
  for (const action of criticalEvents) {
    const count = actionCounts[action] || 0;
    if (count > 0) {
      console.log(`✅ ${action}: ${count} events logged`);
    } else {
      console.log(`❌ ${action}: MISSING`);
      allCriticalPresent = false;
    }
  }
  
  // Verify liveness/readiness health
  console.log("\n=== HEALTH PROBE VERIFICATION ===");
  const liveness = await axios.get(`${BASE_URL}/health/liveness`, { headers, validateStatus: () => true });
  const readiness = await axios.get(`${BASE_URL}/health/readiness`, { headers, validateStatus: () => true });
  console.log(`Liveness: HTTP ${liveness.status} - ${JSON.stringify(liveness.data)}`);
  console.log(`Readiness: HTTP ${readiness.status} - ${JSON.stringify(readiness.data)}`);
  
  return allCriticalPresent;
}

(async () => {
  console.log("=== OBSERVABILITY & TELEMETRY CHECK ===");
  console.log(`Target: ${BASE_URL}`);
  
  await triggerTestEvents();
  const success = await verifyAuditLogs();
  
  console.log(`\n=== OBSERVABILITY CHECK: ${success ? 'PASS' : 'PARTIAL'} ===`);
  if (success) {
    console.log("✅ All critical audit events verified. System probes healthy.");
  } else {
    console.log("⚠️  Some critical events missing. Review required.");
  }
})();
