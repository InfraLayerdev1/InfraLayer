const express = require("express");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const router = express.Router();

// Initialize Supabase client with service role for tenant provisioning
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY
);

/**
 * Generate a secure API key for the new tenant
 * Format: csk_live_<random> (Company Secret Key)
 */
function generateApiKey() {
    const randomBytes = crypto.randomBytes(32).toString("hex");
    return `csk_live_${randomBytes}`;
}

/**
 * Create a new tenant organization in Supabase
 * Reuses the logic from create-tenant.js
 */
async function createTenantFromCheckout(session) {
    const customerEmail = session.customer_details?.email || session.metadata?.customer_email;
    const companyName = session.metadata?.company_name || "New Company";
    const department = session.metadata?.department || "Executive";

    if (!customerEmail) {
        throw new Error("Customer email is required from Stripe session");
    }

    // Pre-flight duplicate guards
    const { data: existingCompany } = await supabase
        .from("companies")
        .select("id, name")
        .eq("name", companyName)
        .maybeSingle();

    if (existingCompany) {
        throw new Error(`Company "${companyName}" already exists`);
    }

    const { data: existingUser } = await supabase
        .from("users")
        .select("id, email")
        .eq("email", customerEmail)
        .maybeSingle();

    if (existingUser) {
        throw new Error(`User with email "${customerEmail}" already exists`);
    }

    // Insert company
    const { data: company, error: companyError } = await supabase
        .from("companies")
        .insert([{ name: companyName }])
        .select("id, name")
        .single();

    if (companyError) {
        throw new Error(`Failed to create company: ${companyError.message}`);
    }

    const tenantId = company.id;

    // Generate temp password for admin
    const tempPassword = generateTempPassword();
    const bcrypt = require("bcrypt");
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    // Insert admin user
    const { data: user, error: userError } = await supabase
        .from("users")
        .insert([{
            email: customerEmail,
            password_hash: hashedPassword,
            full_name: customerEmail.split("@")[0],
            role: "admin",
            status: "active"
        }])
        .select("id, email, role, status")
        .single();

    if (userError) {
        // Rollback company
        await supabase.from("companies").delete().eq("id", tenantId);
        throw new Error(`Failed to create admin user: ${userError.message}`);
    }

    // Insert membership with level 3 (executive)
    const { error: membershipError } = await supabase
        .from("memberships")
        .insert([{
            user_id: user.id,
            company_id: tenantId,
            role: "admin",
            department: department,
            level: "3"
        }]);

    if (membershipError) {
        // Rollback user + company
        await supabase.from("users").delete().eq("id", user.id);
        await supabase.from("companies").delete().eq("id", tenantId);
        throw new Error(`Failed to create membership: ${membershipError.message}`);
    }

    // Generate API key for the tenant
    const apiKey = generateApiKey();

    // Store API key (you could add an api_keys table or use a custom field)
    // For now, we'll return it and the client should store it securely
    // In production, you'd hash this and store in a dedicated api_keys table

    return {
        tenantId,
        companyName,
        adminEmail: customerEmail,
        tempPassword,
        apiKey,
        userId: user.id
    };
}

/**
 * Generate a secure temporary password (16 chars, mixed classes)
 */
function generateTempPassword() {
    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const lower = "abcdefghijkmnpqrstuvwxyz";
    const digits = "23456789";
    const symbols = "!@#$%&*?";

    let password = "";
    password += upper[Math.floor(Math.random() * upper.length)];
    password += lower[Math.floor(Math.random() * lower.length)];
    password += digits[Math.floor(Math.random() * digits.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];

    const all = upper + lower + digits + symbols;
    for (let i = 4; i < 16; i++) {
        password += all[Math.floor(Math.random() * all.length)];
    }

    // Shuffle
    return password.split("").sort(() => Math.random() - 0.5).join("");
}

// ==========================================
// STRIPE WEBHOOK HANDLER
// ==========================================

// Stripe requires the raw body for signature verification
router.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
        console.error("❌ STRIPE_WEBHOOK_SECRET not configured");
        return res.status(500).json({ error: "Webhook secret not configured" });
    }

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.error("❌ Webhook signature verification failed:", err.message);
        return res.status(400).json({ error: `Webhook Error: ${err.message}` });
    }

    // Handle the event
    try {
        switch (event.type) {
            case "checkout.session.completed": {
                const session = event.data.object;
                console.log("✅ Checkout session completed:", session.id);

                // Parse metadata from the session
                const customerEmail = session.customer_details?.email || session.metadata?.customer_email;
                const companyName = session.metadata?.company_name;
                const department = session.metadata?.department || "Executive";

                if (!customerEmail || !companyName) {
                    console.error("❌ Missing required metadata in checkout session");
                    return res.status(400).json({ error: "Missing customer_email or company_name in metadata" });
                }

                // Create tenant
                const tenant = await createTenantFromCheckout(session);

                console.log("🎉 Tenant provisioned successfully:", {
                    tenantId: tenant.tenantId,
                    companyName: tenant.companyName,
                    adminEmail: tenant.adminEmail
                });

                // Log audit event
                await logAuditEvent({
                    action: "TENANT_PROVISIONED_VIA_STRIPE",
                    details: {
                        tenant_id: tenant.tenantId,
                        company_name: tenant.companyName,
                        admin_email: tenant.adminEmail,
                        stripe_session_id: session.id,
                        stripe_customer_id: session.customer
                    }
                });

                // TODO: Send welcome email with credentials to customerEmail
                // For now, credentials are returned in the success page flow

                break;
            }

            case "customer.subscription.deleted": {
                const subscription = event.data.object;
                console.log("📭 Subscription cancelled:", subscription.id);
                // Handle subscription cancellation (downgrade, revoke access, etc.)
                await logAuditEvent({
                    action: "STRIPE_SUBSCRIPTION_CANCELLED",
                    details: { subscription_id: subscription.id, customer_id: subscription.customer }
                });
                break;
            }

            case "invoice.payment_failed": {
                const invoice = event.data.object;
                console.log("💸 Payment failed:", invoice.id);
                await logAuditEvent({
                    action: "STRIPE_PAYMENT_FAILED",
                    details: { invoice_id: invoice.id, customer_id: invoice.customer }
                });
                break;
            }

            default:
                console.log(`ℹ️ Unhandled event type: ${event.type}`);
        }

        res.json({ received: true });
    } catch (err) {
        console.error("❌ Webhook handler error:", err);
        res.status(500).json({ error: "Webhook handler failed" });
    }
});

/**
 * Audit logging helper (mirrors server.js pattern)
 */
async function logAuditEvent({ userId = null, action, details = {} }) {
    try {
        const { error } = await supabase
            .from("audit_logs")
            .insert([{
                user_id: userId,
                action: action,
                details: details,
                created_at: new Date().toISOString()
            }]);

        if (error) {
            console.error("⚠️ [AUDIT LOG ERROR]:", error.message);
        }
    } catch (err) {
        console.error("⚠️ [AUDIT LOG CRITICAL EXCEPTION]:", err.message);
    }
}

module.exports = router;