require("dotenv").config(); const express = require("express"); const axios =
require("axios"); const cors = require("cors"); const bcrypt = require("bcrypt"); const {
createClient } = require("@supabase/supabase-js"); const jwt = require("jsonwebtoken"); const crypto = require("crypto");
const helmet = require("helmet");
const { Ratelimit } = require("@upstash/ratelimit");
const { Redis } = require("@upstash/redis");

// ==========================================
// DOCS ROUTES (OpenAPI 3.1 + Scalar/Swagger UI)
// ==========================================
const docsRouter = require("./routes/docs");

// ===================================
// FAIL-FAST STARTUP VALIDATOR (Phase 9 Block 3)
// Refuses to boot when any required environment variable is missing or blank, so the
// gateway can never run in an insecure / partially-configured state. Runs before the
// Supabase client is constructed and before the server starts listening.
// ===================================
function assertEnvironment() {
    const checks = {
        "SUPABASE_URL": process.env.SUPABASE_URL,
        "SUPABASE_SERVICE_ROLE_KEY (or legacy SUPABASE_KEY)": process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY,
        "JWT_SECRET": process.env.JWT_SECRET
    };
    const missing = Object.entries(checks)
        .filter(([, value]) => !value || !String(value).trim())
        .map(([name]) => name);

    if (missing.length > 0) {
        console.error("\n==============================================================");
        console.error("  ⛔ GATEWAY FAILED TO START — MISSING ENVIRONMENT VARIABLES");
        console.error("==============================================================");
        missing.forEach((name) => console.error(`   ✗ ${name}`));
        console.error("--------------------------------------------------------------");
        console.error("  The gateway requires these variables to operate securely.");
        console.error("  Add them to gateway/.env (or export them) and restart.");
        console.error("==============================================================\n");
        process.exit(1);
    }
}
assertEnvironment();

const app = express();

// ===================================
// SECURITY MIDDLEWARE (Phase 9 Block 3)
// helmet(): standard HTTP security headers (X-Content-Type-Options, X-Frame-Options,
//   Strict-Transport-Security, etc.) on every response.
// cors(): a strict origin allowlist from ALLOWED_ORIGINS (comma-separated; defaults to
//   local dev origins), explicit methods/headers, and credentials enabled.
// ===================================
app.use(helmet());

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000")
    .split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type", "x-access-token"],
    credentials: true
}));
app.use(express.json());

// ==========================================
// DOCS ROUTES - Interactive API Documentation (Scalar/Swagger)
// Mounted early so it's accessible without auth for developer experience
// ==========================================
app.use("/docs", docsRouter);

// ===================================
// SUPABASE & FLOWISE CONFIGURATION
// ===================================
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY
);
const FLOWISE_URL = process.env.FLOWISE_URL;

// JWT signing secret. Production MUST set JWT_SECRET in .env; the dev fallback is a fresh
// random key per boot — secure, but it invalidates every existing token on server restart.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const JWT_EXPIRES_IN = "1h";

// ==========================================
// TOKEN BLACKLIST & UTILITIES
// ==========================================
const tokenBlacklist = new Set();

function extractToken(req) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
        return authHeader.split(" ")[1];
    }
    return req.headers["x-access-token"] || null;
}

// Build the signed JWT (and the matching user object) returned by login/signup.
// The live `users` table has no tenant columns — company/department/access live on
// `memberships` — so those claims are enriched from the caller's membership row when one
// exists. The token is short-lived (1h); the auth middleware still re-checks Supabase live.
function buildAuthResponse(user, membership) {
    const tenant = membership || {};
    const payload = {
        id: user.id,
        email: user.email,
        company_id: tenant.company_id || null,
        role: user.role || "employee",
        department: tenant.department || null,
        access_level: tenant.level ? resolveAccessLevel(tenant.level) : null
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    const userResponse = {
        id: user.id,
        email: user.email,
        full_name: user.full_name || user.email.split("@")[0],
        role: payload.role,
        status: user.status || "active",
        company_id: payload.company_id,
        department: payload.department,
        access_level: payload.access_level
    };
    return { success: true, token, user: userResponse };
}


async function logAuditEvent({ userId = null, action, details = {}, req = null }) {
    try {
        let ip_address = null;
        let user_agent = null;

        if (req) {
            // Extract IP behind proxies (e.g., Nginx, Cloudflare, Render)
            ip_address = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || null;
            user_agent = req.headers['user-agent'] || null;
        }

        const { error } = await supabase
            .from('audit_logs')
            .insert([{
                user_id: userId,
                action: action,
                details: details,
                ip_address: ip_address,
                user_agent: user_agent,
                created_at: new Date().toISOString()
            }]);

        if (error) {
            console.error('⚠️ [AUDIT LOG ERROR]:', error.message);
        }
    } catch (err) {
        // Silently catch so audit failure never crashes main thread
        console.error('⚠️ [AUDIT LOG CRITICAL EXCEPTION]:', err.message);
    }
}


// ==========================================
// RATE LIMITING (Phase 9 Block 1 + Phase 10 Block 4 Patch)
// Dual-key sliding rate limiting with Upstash Redis for distributed serverless compatibility.
// Abuse prevention on the auth routes (per client IP) and on the vector-search chat API
// (per user/token). Every breach is audited.
// ==========================================

// Resolve the client IP the same way logAuditEvent does — first hop of `x-forwarded-for`
// (Nginx/Cloudflare/Render), else the socket address. Using `req.ip` alone would collapse
// every client behind a shared proxy into ONE bucket, so a few attempts by any one user
// would lock the whole org out. We parse the header ourselves.
function getClientIp(req) {
    return req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
        req.socket?.remoteAddress ||
        req.ip ||
        null;
}

// Upstash Redis + Ratelimit for distributed serverless rate limiting.
// Uses fixed-window algorithm (closest to express-rate-limit's sliding behavior for simplicity).
// In serverless, each invocation is stateless — Upstash provides the shared counter.
// Env vars required: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN (set in Vercel dashboard).
let authRatelimit = null;
let apiRatelimit = null;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const redis = new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });

    // Auth limiter: 5 requests / 60 seconds per IP
    authRatelimit = new Ratelimit({
        redis,
        limiter: Ratelimit.fixedWindow(5, "60 s"),
        analytics: true,
        prefix: "rl:auth",
    });

    // API limiter: 30 requests / 60 seconds per user
    apiRatelimit = new Ratelimit({
        redis,
        limiter: Ratelimit.fixedWindow(30, "60 s"),
        analytics: true,
        prefix: "rl:api",
    });

    console.log("✅ Upstash Redis rate limiting initialized (distributed serverless mode)");
} else {
    console.warn("⚠️ UPSTASH_REDIS_REST_URL/TOKEN not set — rate limiting will use in-memory fallback (NOT serverless-safe)");
    // In-memory fallback for local dev without Upstash (not for production serverless)
    const { FixedWindow } = require("@upstash/ratelimit");
    const memoryStore = new Map();

    authRatelimit = {
        limit: async (key) => {
            const now = Date.now();
            const windowStart = now - 60 * 1000;
            const entry = memoryStore.get(key) || { count: 0, windowStart: now };
            if (entry.windowStart < windowStart) {
                entry.count = 0;
                entry.windowStart = now;
            }
            entry.count++;
            memoryStore.set(key, entry);
            const remaining = Math.max(0, 5 - entry.count);
            const reset = entry.windowStart + 60 * 1000;
            return { success: entry.count <= 5, limit: 5, remaining, reset };
        }
    };

    apiRatelimit = {
        limit: async (key) => {
            const now = Date.now();
            const windowStart = now - 60 * 1000;
            const entry = memoryStore.get(key) || { count: 0, windowStart: now };
            if (entry.windowStart < windowStart) {
                entry.count = 0;
                entry.windowStart = now;
            }
            entry.count++;
            memoryStore.set(key, entry);
            const remaining = Math.max(0, 30 - entry.count);
            const reset = entry.windowStart + 60 * 1000;
            return { success: entry.count <= 30, limit: 30, remaining, reset };
        }
    };
}

// IP-based auth limiter middleware: 5 attempts / 60s per client IP on /auth/login & /auth/signup.
async function authRateLimiter(req, res, next) {
    const ip = getClientIp(req) || "unknown-ip";
    const key = `ip:${ip}`;

    const { success, limit, remaining, reset } = await authRatelimit.limit(key);

    // Emit RateLimit-* headers (draft 8)
    res.setHeader("RateLimit-Limit", limit);
    res.setHeader("RateLimit-Remaining", remaining);
    res.setHeader("RateLimit-Reset", Math.ceil(reset / 1000));

    if (!success) {
        await logAuditEvent({
            userId: null,
            action: 'RATE_LIMIT_EXCEEDED',
            details: { endpoint: req.originalUrl, ip },
            req
        });
        return res.status(429).json({ error: "Too many authentication attempts. Please try again in 60 seconds." });
    }
    next();
}

// Token-based API limiter middleware: 30 requests / 60s per authenticated user on the vector-search
// chat endpoint (/ask). Mounted AFTER verifyActiveAccountAndToken so req.currentUser is
// populated (this codebase sets req.currentUser, not req.user) and keying is per-user
// rather than per-IP — token rotation cannot bypass the shared per-user bucket.
async function apiRateLimiter(req, res, next) {
    const userId = req.currentUser?.id || "anonymous";
    const key = `user:${userId}`;

    const { success, limit, remaining, reset } = await apiRatelimit.limit(key);

    // Emit RateLimit-* headers (draft 8)
    res.setHeader("RateLimit-Limit", limit);
    res.setHeader("RateLimit-Remaining", remaining);
    res.setHeader("RateLimit-Reset", Math.ceil(reset / 1000));

    if (!success) {
        await logAuditEvent({
            userId: req.currentUser?.id || null,
            action: 'RATE_LIMIT_EXCEEDED',
            details: { endpoint: req.originalUrl },
            req
        });
        return res.status(429).json({ error: "API rate limit exceeded. Please throttle your requests." });
    }
    next();
}


// ==========================================
// DOCUMENT METADATA INGESTION HELPER
// ==========================================
async function ingestDocumentWithMetadata({ companyId, filename, department, minAccessLevel, chunksWithEmbeddings }) {
    const docDepartment = department || 'ALL';
    const docMinAccessLevel = minAccessLevel || 1;
    const chunks = chunksWithEmbeddings || [];

    // 1. Insert the document row and extract its id.
    //    The live `documents` table is (id, company_id, department, title, content) — it has no
    //    filename/min_access_level columns, so `filename` maps to `title` and the security metadata
    //    lives on the chunks below (which is what the retrieval RPC filters on).
    const { data: document, error: docError } = await supabase
        .from("documents")
        .insert([{
            company_id: companyId,
            title: filename,
            department: docDepartment,
            content: chunks.map((c) => c.content).join("\n")
        }])
        .select("id")
        .single();

    if (docError) {
        throw new Error(`Failed to create document record: ${docError.message}`);
    }

    const documentId = document.id;

    // 2. Map chunks to carry the parent's metadata context on every row
    const rows = chunks.map((chunk) => ({
        document_id: documentId,
        company_id: companyId,
        department: docDepartment,
        min_access_level: docMinAccessLevel,
        content: chunk.content,
        embedding: chunk.embedding
    }));

    // 3. Batch insert into document_chunks
    const { error: chunksError } = await supabase
        .from("document_chunks")
        .insert(rows);

    if (chunksError) {
        throw new Error(`Failed to insert document chunks: ${chunksError.message}`);
    }

    // 4. Audit the ingestion boundary (userId null: this is an admin-driven ingest)
    await logAuditEvent({
        userId: null,
        action: 'DOCUMENT_INGESTED',
        details: {
            filename,
            company_id: companyId,
            department: docDepartment,
            min_access_level: docMinAccessLevel,
            chunk_count: rows.length
        }
    });

    return { documentId, chunkCount: rows.length };
}


// ==========================================
// EMBEDDING GENERATOR (OpenAI, optional)
// ==========================================
// Mirrors the FLOWISE_URL convention: the provider is optional. With no OPENAI_API_KEY the
// generator returns null and retrieval is skipped — sending no context is safer than a fake vector.
async function generateEmbedding(text) {
    const apiKey = process.env.OPENAI_API_KEY || process.env.OPENAI_EMBEDDING_API_KEY;
    if (!apiKey) {
        console.warn("⚠️ No OPENAI_API_KEY set — skipping RAG retrieval for this question.");
        return null;
    }

    const model = process.env.OPENAI_EMBEDDING_MODEL || "text-embedding-3-small";
    try {
        const res = await axios.post("https://api.openai.com/v1/embeddings", {
            model,
            input: text
        }, {
            headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" }
        });
        return res.data?.data?.[0]?.embedding || null;
    } catch (err) {
        console.error("EMBEDDING GENERATION ERROR:", err.response?.data?.error?.message || err.message);
        return null;
    }
}


// ==========================================
// ACCESS LEVEL RESOLVER
// ==========================================
// memberships.level is a free-form label (e.g. "Manager"). A non-numeric label maps to 1 — the
// most restrictive tier — so an unknown level can never OVER-grant access (security-safe direction).
function resolveAccessLevel(level) {
    if (typeof level === "number" && Number.isFinite(level) && level >= 1) return level;
    if (typeof level === "string" && /^\d+$/.test(level.trim())) return parseInt(level, 10);
    if (level != null && level !== "") {
        console.warn(`⚠️ Non-numeric access level "${level}" defaulting to 1 (most restrictive).`);
    }
    return 1;
}


// ==========================================
// PRE-LLM RETRIEVAL ENGINE (Metadata-Aware)
// ==========================================
// Security rule: the gateway only ever retrieves chunks that pass the user's metadata context
// (company_id + department + access_level). Flowise/LLM never sees anything else.
async function retrieveClearedContext({ queryVector, companyId, department, accessLevel, topK = 5, similarityThreshold = 0.5 }) {
    const { data, error } = await supabase.rpc("match_document_chunks", {
        query_embedding: queryVector,
        match_threshold: similarityThreshold,
        match_count: topK,
        p_company_id: companyId,
        p_department: department,
        p_access_level: accessLevel
    });

    if (error) {
        throw new Error(`RAG retrieval failed: ${error.message}`);
    }
    return data || [];
}


// ==========================================
// SECURITY GUARD: REAL-TIME USER & TOKEN VERIFICATION
// ==========================================
const verifyActiveAccountAndToken = async (req, res, next) => {
    try {
        const token = extractToken(req);

        // 1. A token is REQUIRED. The signed JWT is the sole identity — the legacy
        //    params/query/body userId resolution is gone (it let any caller claim any
        //    userId without proving who they were; closing that gap is the point of the
        //    JWT migration). Every real client (index.html request()) sends a token.
        if (!token) {
            return res.status(401).json({ error: "Access Denied: Missing authentication token." });
        }

        // 2. Stateful revocation: tokens blacklisted on logout are dead on sight
        if (tokenBlacklist.has(token)) {
            return res.status(401).json({
                error: "Session Invalidated: Token has been revoked. Please log in again."
            });
        }

        // 3. Verify the JWT signature + expiry. A valid payload IS the caller's identity.
        let payload;
        try {
            payload = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(401).json({ error: "Token expired. Please log in again." });
            }
            // Tampered, malformed, or garbage token — log the attempt and refuse
            await logAuditEvent({
                userId: null,
                action: 'INVALID_TOKEN_ATTEMPT',
                details: { reason: err.message, path: req.originalUrl },
                req
            });
            return res.status(401).json({ error: "Invalid authentication token." });
        }

        const userId = payload.id;
        if (!userId) {
            return res.status(401).json({ error: "Access Denied: Invalid authentication token." });
        }

        // 4. Real-time kill switch: re-check the users row live (deleted → 401 + blacklist;
        //    terminated/deactivated → 403 + blacklist). Authorization always comes from the DB,
        //    never from the (possibly stale) JWT claims.
        const { data: user, error } = await supabase
            .from("users")
            .select("id, status, role, email")
            .eq("id", userId)
            .maybeSingle();

        // Account missing/deleted
        if (error || !user) {
            tokenBlacklist.add(token);
            return res.status(401).json({
                error: "Account Not Found: This account no longer exists. Please sign up again."
            });
        }

        // Account terminated or deactivated
        if (user.status === "terminated" || user.status === "deactivated") {
            tokenBlacklist.add(token);
            return res.status(403).json({
                error: "Access Revoked: Your account has been terminated. Contact system admin."
            });
        }

        req.currentUser = user;
        next();
    } catch (err) {
        console.error("Security Guard Error:", err);
        return res.status(500).json({ error: "Internal security enforcement failure." });
    }
};

// ==========================================
// ADMIN GUARD: RBAC CHECK (runs AFTER verifyActiveAccountAndToken)
// ==========================================
const requireAdmin = async (req, res, next) => {
    const user = req.currentUser;
    if (!user || user.role !== "admin") {
        await logAuditEvent({ userId: user?.id || null, action: 'UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', details: { path: req.originalUrl }, req });
        return res.status(403).json({ error: "Access Denied: Administrative privileges required." });
    }
    next();
};

// ===================================
// HEALTH PROBES (Phase 9 Block 4)
// Public, unauthenticated and unrate-limited so load balancers / orchestrators can poll
// them freely. Liveness: the process is up. Readiness: the gateway can actually reach
// Supabase — a failed probe marks the instance unready (503) so traffic gets drained.
// ===================================
app.get("/health/liveness", (req, res) => {
    res.status(200).json({ status: "alive", timestamp: new Date().toISOString() });
});

app.get("/health/readiness", async (req, res) => {
    try {
        const { error } = await supabase
            .from("companies")
            .select("count", { count: "exact", head: true });
        if (error) throw error;
        res.status(200).json({ status: "ready", database: "connected", timestamp: new Date().toISOString() });
    } catch (err) {
        await logAuditEvent({
            action: "DATABASE_DISCONNECTED",
            details: { message: err.message, path: req.originalUrl },
            req
        });
        res.status(503).json({ status: "unready", database: "disconnected" });
    }
});

// ===================================
// AUTHENTICATION ROUTES
// ===================================
app.post("/auth/signup", authRateLimiter, async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userRole = role || "employee";

        // Create user row with active status
        const { data: newUser, error: userError } = await supabase
            .from("users")
            .insert([{ 
                email, 
                password_hash: hashedPassword, 
                full_name: full_name || email.split("@")[0],
                role: userRole,
                status: "active" 
            }])
            .select("id, email, full_name, role, status")
            .single();

        if (userError) {
            return res.status(400).json({ error: userError.message });
        }

        await logAuditEvent({ userId: newUser.id, action: 'USER_REGISTERED', details: { email }, req });

        // Auto-login: issue the same short-lived JWT as login. A brand-new user has no
        // membership yet (membership inserts are RLS-blocked), so tenant claims are null.
        return res.status(201).json(buildAuthResponse(newUser, null));
    } catch (err) {
        console.error("Signup error:", err);
        return res.status(500).json({ error: "Signup failed." });
    }
});

app.post("/auth/login", authRateLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        const { data: user, error } = await supabase
            .from("users")
            .select("*")
            .eq("email", email)
            .maybeSingle();

        if (error || !user) {
            await logAuditEvent({ userId: null, action: 'USER_LOGIN_FAILED', details: { email, reason: 'Invalid credentials' }, req });
            return res.status(401).json({ error: "Invalid email or password." });
        }

        if (user.status === "terminated" || user.status === "deactivated") {
            await logAuditEvent({ userId: user.id, action: 'USER_LOGIN_BLOCKED', details: { email, reason: 'Account terminated' }, req });
            return res.status(403).json({ error: "Account terminated or deactivated. Access revoked." });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash || user.password || "");
        if (!validPassword) {
            await logAuditEvent({ userId: user.id, action: 'USER_LOGIN_FAILED', details: { email, reason: 'Invalid credentials' }, req });
            return res.status(401).json({ error: "Invalid email or password." });
        }

        await logAuditEvent({ userId: user.id, action: 'USER_LOGIN_SUCCESS', details: { email: user.email, role: user.role }, req });

        // Best-effort tenant context for the JWT (memberships may not exist for every user)
        const { data: membership } = await supabase
            .from("memberships")
            .select("company_id, department, level")
            .eq("user_id", user.id)
            .limit(1)
            .maybeSingle();

        return res.status(200).json(buildAuthResponse(user, membership || null));
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ error: "Login failed." });
    }
});

app.post("/auth/logout", async (req, res) => {
    const token = extractToken(req);
    let userId = null;
    if (token) {
        tokenBlacklist.add(token); // stateful revocation: dead until server restart
        try {
            userId = jwt.verify(token, JWT_SECRET).id || null;
        } catch {
            // Token may already be expired — still decode it (no signature check) for audit attribution
            try { userId = jwt.decode(token)?.id || null; } catch { userId = null; }
        }
    }
    await logAuditEvent({ userId, action: 'USER_LOGOUT', details: { revoked: !!token }, req });
    return res.status(200).json({ success: true, message: "Logged out successfully." });
});

// ===================================
// SESSION MANAGEMENT ROUTES
// ===================================

// Handler: List Sessions
const listSessionsHandler = async (req, res) => {
    try {
        // Identity comes from the verified JWT (req.currentUser), never from a client-supplied
        // :userId — otherwise any authenticated user could list another user's sessions.
        const userId = req.currentUser?.id;
        if (!userId) {
            return res.status(400).json({ error: "userId is required." });
        }

        const { data, error } = await supabase
            .from("chat_sessions")
            .select("id, title, created_at, updated_at")
            .eq("user_id", userId)
            .order("updated_at", { ascending: false });

        if (error) {
            console.error("LIST SESSIONS ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        return res.json(data || []);
    } catch (error) {
        console.error("LIST SESSIONS ERROR:", error);
        return res.status(500).json({ error: error.message });
    }
};

// Handler: Create Session
const createSessionHandler = async (req, res) => {
    try {
        const userId = req.currentUser?.id || req.body?.user_id || req.body?.userId;
        if (!userId) {
            return res.status(400).json({ error: "user_id is required." });
        }

        const { data, error } = await supabase
            .from("chat_sessions")
            .insert([{
                user_id: userId,
                title: req.body?.title || "New Conversation"
            }])
            .select("id, title, created_at, updated_at")
            .single();

        if (error) {
            console.error("SESSION CREATE ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        return res.status(201).json(data);
    } catch (error) {
        console.error("SESSION CREATE ERROR:", error);
        return res.status(500).json({ error: error.message });
    }
};

// Handler: Get Messages
const getMessagesHandler = async (req, res) => {
    try {
        const { session_id } = req.params;
        if (!session_id) {
            return res.status(400).json({ error: "session_id is required." });
        }

        const { data, error } = await supabase
            .from("chat_messages")
            .select("*")
            .eq("session_id", session_id)
            .order("created_at", { ascending: true });

        if (error) {
            console.error("GET MESSAGES ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        return res.json(data || []);
    } catch (error) {
        console.error("GET MESSAGES ERROR:", error);
        return res.status(500).json({ error: error.message });
    }
};

// Register Session Routes
app.get("/session/:userId", verifyActiveAccountAndToken, listSessionsHandler);
app.get("/sessions/:userId", verifyActiveAccountAndToken, listSessionsHandler);
app.get("/sessions", verifyActiveAccountAndToken, listSessionsHandler);
app.post("/session", verifyActiveAccountAndToken, createSessionHandler);
app.post("/sessions", verifyActiveAccountAndToken, createSessionHandler);
app.get("/message/:session_id", verifyActiveAccountAndToken, getMessagesHandler);
app.get("/messages/:session_id", verifyActiveAccountAndToken, getMessagesHandler);

// Rename Session
app.patch("/sessions/:session_id", verifyActiveAccountAndToken, async (req, res) => {
    const { session_id } = req.params;
    const { title } = req.body;
    const { data, error } = await supabase
        .from("chat_sessions")
        .update({ title, updated_at: new Date().toISOString() })
        .eq("id", session_id)
        .select();

    if (error) return res.status(500).json(error);
    return res.json(data);
});

// RBAC Protected: Delete Session
app.delete("/sessions/:session_id", verifyActiveAccountAndToken, async (req, res) => {
    try {
        const { session_id } = req.params;
        const requester = req.currentUser;

        // Fetch session to check ownership
        const { data: targetSession, error: fetchError } = await supabase
            .from("chat_sessions")
            .select("id, user_id, title")
            .eq("id", session_id)
            .maybeSingle();

        if (fetchError || !targetSession) {
            return res.status(404).json({ error: "Conversation session not found." });
        }

        const isAdmin = requester.role === "admin";
        const isOwner = targetSession.user_id === requester.id;

        if (!isAdmin && !isOwner) {
            return res.status(403).json({ 
                error: "Access Denied: You do not own this conversation and lack administrator permissions." 
            });
        }

        const { error: deleteError } = await supabase
            .from("chat_sessions")
            .delete()
            .eq("id", session_id);

        if (deleteError) {
            console.error("Delete Session Error:", deleteError);
            return res.status(500).json({ error: deleteError.message });
        }

        await logAuditEvent({ userId: requester.id, action: 'SESSION_DELETED', details: { session_id }, req });

        return res.status(200).json({
            success: true,
            message: `Conversation '${targetSession.title || 'Chat'}' deleted.`
        });
    } catch (err) {
        console.error("Delete Session Error:", err);
        return res.status(500).json({ error: "Internal server error during deletion." });
    }
});

// ===================================
// CHAT & AI EXECUTION ROUTE
// ===================================
app.post("/ask", verifyActiveAccountAndToken, apiRateLimiter, async (req, res) => {
    try {
        const { user_id, session_id, question } = req.body;

        if (!user_id || !session_id || !question) {
            return res.status(400).json({ error: "user_id, session_id, and question are required." });
        }

        // Save User Message
        const { error: userMsgError } = await supabase
            .from("chat_messages")
            .insert([{
                session_id,
                sender: "user",
                content: question
            }]);

        if (userMsgError) console.error("Error saving user message:", userMsgError);

        // ===========================================
        // PRE-LLM SECURITY FILTER: tenant-scoped retrieval
        // Only chunks cleared by the user's metadata context may reach Flowise.
        // ===========================================
        let contextBlock = null;
        let chunksFound = 0;
        let retrievalCompanyId = null;
        try {
            // Resolve the user's membership context (company_id, department, level)
            const { data: membership, error: membershipError } = await supabase
                .from("memberships")
                .select("company_id, department, level")
                .eq("user_id", req.currentUser.id)
                .limit(1)
                .maybeSingle();

            if (membershipError) {
                console.error("RAG MEMBERSHIP LOOKUP ERROR:", membershipError.message);
            } else if (membership && membership.company_id) {
                retrievalCompanyId = membership.company_id;
                const department = membership.department || 'ALL';
                const accessLevel = resolveAccessLevel(membership.level);

                const queryVector = await generateEmbedding(question);
                if (queryVector) {
                    const chunks = await retrieveClearedContext({
                        queryVector,
                        companyId: retrievalCompanyId,
                        department,
                        accessLevel
                    });
                    chunksFound = chunks.length;
                    if (chunksFound > 0) {
                        const contextText = chunks.map((c) => c.content).join("\n");
                        contextBlock = `[DOCUMENT CONTEXT: ${contextText} ]`;
                    }
                }
            }
        } catch (retrievalErr) {
            // Retrieval failure must never break the chat: fall through with no context
            console.error("RAG RETRIEVAL ERROR:", retrievalErr.message);
        }

        // Audit every retrieval verdict, including denials and no-membership cases
        await logAuditEvent({
            userId: req.currentUser.id,
            action: 'RAG_CONTEXT_RETRIEVED',
            details: { company_id: retrievalCompanyId, chunks_found: chunksFound },
            req
        });

        // Fetch AI Response (Flowise or Fallback)
        let aiResponseText = `Processing request for: "${question}"`;
        if (FLOWISE_URL) {
            try {
                const flowiseRes = await axios.post(FLOWISE_URL, {
                    question: contextBlock ? `${contextBlock}\n\nQuestion: ${question}` : question,
                    overrideConfig: { sessionId: session_id }
                });
                aiResponseText = flowiseRes.data?.text || flowiseRes.data || aiResponseText;
            } catch (fErr) {
                console.warn("Flowise call failed, using echo response:", fErr.message);
                aiResponseText = `Knowledge Base Response: Handled question "${question}".`;
            }
        }

        // Save Bot Response
        const { error: aiMsgError } = await supabase
            .from("chat_messages")
            .insert([{
                session_id,
                sender: "bot",
                content: aiResponseText
            }]);

        if (aiMsgError) console.error("Error saving bot message:", aiMsgError);

        // Update Session Timestamp
        await supabase
            .from("chat_sessions")
            .update({ updated_at: new Date().toISOString() })
            .eq("id", session_id);

        return res.json({ text: aiResponseText, session_id });

    } catch (err) {
        console.error("Ask endpoint error:", err);
        return res.status(500).json({ error: err.message || "Failed to process question." });
    }
});

// ==========================================
// ADMIN ROUTES (requireAdmin = admin role only)
// ==========================================

// List all users (admin only)
app.get("/admin/users", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from("users")
            .select("id, email, role, status, created_at")
            .order("created_at", { ascending: false });

        if (error) {
            console.error("ADMIN LIST USERS ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        await logAuditEvent({ userId: req.currentUser.id, action: 'ADMIN_PANEL_ACCESS', details: { section: 'user_management' }, req });

        return res.json(data || []);
    } catch (err) {
        console.error("ADMIN LIST USERS ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
});

// Delete a user (admin only)
app.delete("/admin/users/:userId", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const requester = req.currentUser;

        if (userId === requester.id) {
            return res.status(400).json({ error: "Cannot delete your own account." });
        }

        const { data: existing, error: getErr } = await supabase
            .from("users")
            .select("id, email, role")
            .eq("id", userId)
            .maybeSingle();

        if (getErr) {
            console.error("ADMIN DELETE USER GET ERROR:", getErr);
            return res.status(500).json({ error: getErr.message });
        }
        if (!existing) {
            return res.status(404).json({ error: "User not found." });
        }

        // Prevent deleting the last admin (safety check)
        if (existing.role === "admin") {
            const { data: admins, error: adminErr } = await supabase
                .from("users")
                .select("id")
                .eq("role", "admin")
                .eq("status", "active");
            if (!adminErr && admins && admins.length <= 1) {
                return res.status(400).json({ error: "Cannot delete the last active admin." });
            }
        }

        const { error: delErr } = await supabase
            .from("users")
            .delete()
            .eq("id", userId);

        if (delErr) {
            console.error("ADMIN DELETE USER ERROR:", delErr);
            return res.status(500).json({ error: delErr.message });
        }

        await logAuditEvent({
            userId: requester.id,
            action: 'ADMIN_USER_DELETED',
            details: { deleted_user_id: userId, deleted_user_email: existing.email },
            req
        });

        return res.json({ success: true, message: `User '${existing.email}' deleted.` });
    } catch (err) {
        console.error("ADMIN DELETE USER ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
});

// Update a user's role/status (admin only)
app.patch("/admin/users/:userId", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { role, status } = req.body || {};

        const updates = {};
        if (role !== undefined) updates.role = role;

        if (status !== undefined) {
            const validStatuses = ["active", "deactivated", "terminated"];
            if (!validStatuses.includes(status)) {
                return res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(", ")}.` });
            }
            updates.status = status;
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ error: "No valid fields provided. Provide role and/or status." });
        }

        const { data, error } = await supabase
            .from("users")
            .update(updates)
            .eq("id", userId)
            .select("id, email, role, status, created_at")
            .maybeSingle();

        if (error) {
            console.error("ADMIN UPDATE USER ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        if (!data) {
            return res.status(404).json({ error: "User not found." });
        }

        await logAuditEvent({ userId: req.currentUser.id, action: 'ADMIN_USER_UPDATED', details: { target_user_id: userId, updated_fields: updates }, req });

        return res.json(data);
    } catch (err) {
        console.error("ADMIN UPDATE USER ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
});

// List recent audit log entries (admin only)
app.get("/admin/audit-logs", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from("audit_logs")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(100);

        if (error) {
            console.error("ADMIN LIST AUDIT LOGS ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        await logAuditEvent({ userId: req.currentUser.id, action: 'ADMIN_PANEL_ACCESS', details: { section: 'audit_trail' }, req });

        return res.json(data || []);
    } catch (err) {
        console.error("ADMIN LIST AUDIT LOGS ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
});

// Ingest a document with metadata context (admin only)
app.post("/admin/documents/ingest", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        const { company_id, filename, department, min_access_level, chunks } = req.body || {};

        if (!company_id || !filename || !Array.isArray(chunks) || chunks.length === 0) {
            return res.status(400).json({ error: "company_id, filename, and a non-empty chunks array are required." });
        }

        // Ensure every chunk has a vector: generate one server-side when the caller (e.g. the
        // Knowledge Vault UI) provides content only. Requires an embedding provider to be configured.
        const prepared = [];
        for (const c of chunks) {
            let embedding = Array.isArray(c.embedding) ? c.embedding : null;
            if (c.content && !embedding) {
                embedding = await generateEmbedding(c.content);
            }
            if (!(c.content) || !embedding) {
                return res.status(400).json({ error: "Each chunk needs .content and an .embedding (or set OPENAI_API_KEY so the gateway can generate one)." });
            }
            prepared.push({ content: c.content, embedding });
        }

        const result = await ingestDocumentWithMetadata({
            companyId: company_id,
            filename,
            department,
            minAccessLevel: min_access_level,
            chunksWithEmbeddings: prepared
        });

        return res.status(201).json({
            success: true,
            message: `Document '${filename}' ingested with ${result.chunkCount} chunk(s).`,
            document_id: result.documentId,
            chunk_count: result.chunkCount
        });
    } catch (err) {
        console.error("ADMIN INGEST DOCUMENT ERROR:", err.message);
        return res.status(500).json({ error: err.message || "Failed to ingest document." });
    }
});

// List all documents (admin only)
app.get("/admin/documents", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        // NOTE: the live `documents` table has no timestamp column — order by id for a stable list.
        const { data, error } = await supabase
            .from("documents")
            .select("*")
            .order("id", { ascending: false });

        if (error) {
            console.error("ADMIN LIST DOCUMENTS ERROR:", error);
            return res.status(500).json({ error: error.message });
        }

        // Security metadata (min access level) + count live on the chunks, not the container row.
        // Aggregate them per document so the roster can render the Access Level badge.
        const docs = data || [];
        let agg = new Map();
        if (docs.length > 0) {
            const { data: chunkAggs, error: aggError } = await supabase
                .from("document_chunks")
                .select("document_id, min_access_level");
            if (aggError) {
                console.error("ADMIN DOCUMENT CHUNK AGG ERROR:", aggError.message);
            } else if (chunkAggs) {
                for (const c of chunkAggs) {
                    if (!agg.has(c.document_id)) agg.set(c.document_id, { min: Infinity, count: 0 });
                    const a = agg.get(c.document_id);
                    const lvl = c.min_access_level ?? 1;
                    if (lvl < a.min) a.min = lvl;
                    a.count += 1;
                }
            }
        }
        const enriched = docs.map(d => {
            const a = agg.get(d.id);
            return { ...d, access_level: a ? a.min : null, chunk_count: a ? a.count : 0 };
        });

        await logAuditEvent({ userId: req.currentUser.id, action: 'ADMIN_PANEL_ACCESS', details: { section: 'documents' }, req });

        return res.json(enriched);
    } catch (err) {
        console.error("ADMIN LIST DOCUMENTS ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
});

// Delete a document and its chunks (admin only)
app.delete("/admin/documents/:docId", verifyActiveAccountAndToken, requireAdmin, async (req, res) => {
    try {
        const { docId } = req.params;

        const { data: existing, error: getErr } = await supabase
            .from("documents")
            .select("id, title, department")
            .eq("id", docId)
            .maybeSingle();

        if (getErr) {
            console.error("ADMIN DELETE DOCUMENT GET ERROR:", getErr);
            return res.status(500).json({ error: getErr.message });
        }
        if (!existing) {
            return res.status(404).json({ error: "Document not found." });
        }

        // Chunks reference the document (FK); delete them first.
        await supabase.from("document_chunks").delete().eq("document_id", docId);

        const { error: delErr } = await supabase.from("documents").delete().eq("id", docId);
        if (delErr) {
            console.error("ADMIN DELETE DOCUMENT ERROR:", delErr);
            return res.status(500).json({ error: delErr.message });
        }

        await logAuditEvent({
            userId: req.currentUser.id,
            action: 'DOCUMENT_DELETED',
            details: { document_id: docId, title: existing.title, department: existing.department },
            req
        });

        return res.json({ success: true, message: `Document '${existing.title}' deleted.` });
    } catch (err) {
        console.error("ADMIN DELETE DOCUMENT ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
});

// ==========================================
// STATIC FILE SERVING (must be AFTER all API routes)
// ==========================================
// Serve static frontend files from project root
const path = require('path');
app.use(express.static(path.join(__dirname, '..')));

// ===================================
// SANITIZED GLOBAL ERROR HANDLER (Phase 9 Block 3)
// Express 5 forwards any uncaught route error here. We log the full stack internally
// (console + audit) but never ship stack traces or internal details to clients: admins
// get the error message, everyone else a generic 500. If a response already started,
// hand off to Express' default handler instead of double-sending.
// ===================================
app.use((err, req, res, next) => {
    console.error("Unhandled server error:", err);
    logAuditEvent({
        userId: req.currentUser?.id || null,
        action: "SERVER_ERROR",
        details: { message: err.message, stack: err.stack, path: req.originalUrl },
        req
    });
    if (res.headersSent) {
        return next(err);
    }
    const isAdmin = req.currentUser?.role === "admin";
    return res.status(isAdmin ? (err.status || 500) : 500).json({
        error: isAdmin ? err.message : "An unexpected internal server error occurred."
    });
});

// Start Server (only when run directly, not when imported as serverless module)
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
    });
}

// Serverless export for Vercel / AWS Lambda / etc.
module.exports = app;

// ===================================
// GLOBAL PROCESS EXCEPTION & CRASH TELEMETRY (Phase 9 Block 4)
// Captures uncaught exceptions and unhandled promise rejections into the audit log so a
// crash is never silent, then re-raises the fatal crash (non-zero exit) instead of
// suppressing it — an orchestrator / process manager is expected to restart the gateway.
// ===================================
function logCrashTelemetry(label, error) {
    const message = (error && error.message) ? error.message : String(error);
    const stack = (error && error.stack) ? error.stack : message;
    console.error("\n==============================================================");
    console.error(`  🔴 ${label}`);
    console.error("==============================================================");
    console.error(stack);
    console.error("==============================================================\n");
    // Return the audit promise so the caller can exit only after it settles.
    // logAuditEvent never throws, so telemetry can't break the crash path.
    return logAuditEvent({ action: "SYSTEM_CRASH_PREVENTED", details: { message, stack } });
}

// Exit once the audit write settles (so the row is not lost to a race), with a hard
// 1.5s cap so a hung Supabase can never stop the fatal crash from completing.
function exitAfterTelemetry(auditPromise) {
    const hardLimit = setTimeout(() => process.exit(1), 1500);
    auditPromise.finally(() => { clearTimeout(hardLimit); process.exit(1); });
}

process.on("uncaughtException", (error) => {
    exitAfterTelemetry(logCrashTelemetry("UNCAUGHT EXCEPTION — telemetry captured, shutting down", error));
});

process.on("unhandledRejection", (reason) => {
    exitAfterTelemetry(logCrashTelemetry("UNHANDLED PROMISE REJECTION — telemetry captured, shutting down", reason));
});
