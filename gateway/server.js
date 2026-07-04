require("dotenv").config();

const express = require("express");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(express.json());


// ===================================
// SUPABASE
// ===================================

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);


// ===================================
// FLOWISE
// ===================================

const FLOWISE_URL = process.env.FLOWISE_URL;


// ===================================
// ASK ROUTE
// ===================================

app.post("/ask", async (req, res) => {

    try {

        const {

            user_id,
            question

        } = req.body;


        console.log("\n====================");
        console.log("QUESTION:");
        console.log(question);
        console.log("====================");


        // ===================================
        // 1. MEMBERSHIP
        // ===================================

        const {

            data: memberships,
            error: membershipError

        } = await supabase
            .from("memberships")
            .select("*")
            .eq("user_id", user_id);


        if (membershipError) {

            console.log("MEMBERSHIP ERROR:");
            console.log(membershipError);

            return res.status(500).json({

                error: membershipError.message

            });

        }


        if (!memberships || memberships.length === 0) {

            return res.status(404).json({

                error: "No membership found"

            });

        }


        const user = memberships[0];


        console.log("\nUSER:");
        console.log(user);


        // ===================================
        // 2. DOCUMENTS
        // ===================================

        const {

            data: documents,
            error: documentError

        } = await supabase
            .from("documents")
            .select("*")
            .eq("company_id", user.company_id);


        if (documentError) {

            console.log("\nDOCUMENT ERROR:");
            console.log(documentError);

            return res.status(500).json({

                error: documentError.message

            });

        }


        console.log("\nRAW DOCUMENTS:");
        console.log(documents);


        // ===================================
        // 3. PERMISSION FILTER
        // ===================================

        const filteredDocuments = (documents || []).filter(doc => {

    // Company boundary
    if (doc.company_id !== user.company_id) {
        return false;
    }

    // Role restriction
    if (doc.role && doc.role !== user.role) {
        return false;
    }

    // Department restriction
    if (doc.department && doc.department !== user.department) {
        return false;
    }

    // Level restriction
    if (doc.level && doc.level !== user.level) {
        return false;
    }

    return true;

}); 


        console.log("\nFILTERED DOCUMENTS:");
        console.log(filteredDocuments);


        // ===================================
        // 4. BUILD CONTEXT
        // ===================================

        const context = filteredDocuments
            .map(doc => {

                return `TITLE:
${doc.title}

CONTENT:
${doc.content}`;

            })
            .join("\n\n");


        console.log("\nAI CONTEXT:");
        console.log(context);


        // ===================================
        // 5. FLOWISE
        // ===================================


console.log("SENDING TO FLOWISE:");
console.log({
    question,
    context
});


        const flowiseResponse = await axios.post(
            FLOWISE_URL,
            {
                question,
                context
            }
        );


        console.log("\nFLOWISE RESPONSE:");
        console.log(flowiseResponse.data);


        // ===================================
        // 6. RETURN RESPONSE
        // ===================================

        return res.json({

            question,

            user,

            context,

            answer: flowiseResponse.data

        });

    } catch (error) {

        console.log("\nFULL ERROR:");
        console.log(
            error.response?.data ||
            error.message
        );

        return res.status(500).json({

            error:
                error.response?.data ||
                error.message

        });

    }

});

// ===================================
// SERVER
// ===================================

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {

    console.log("\n==================================");
    console.log("Company AI Gateway Running");
    console.log("Port:", PORT);
    console.log("==================================");

});
