# Final Architecture

## 1. Frontend

Question:

What does the user interact with?

Answer:

The frontend is where the user asks questions and receives answers.

Example:

User asks:
"What is our PTO policy?"

The frontend sends the question to the Gateway.

---

## 2. Gateway

Question:

Why do we need a Gateway?

Answer:

The Gateway is the security and control layer.

It checks:

- Who is asking?
- Which company are they from?
- What role do they have?
- What information are they allowed to access?

The Gateway prepares the request before sending it to the AI.

---

## 3. Supabase

Question:

What does Supabase do?

Answer:

Supabase stores:

- users
- companies
- memberships
- documents
- permissions

It decides what information the user can access.

It does not generate answers.

---

## 4. Flowise

Question:

What does Flowise do?

Answer:

Flowise is the AI answer generator.

It receives:

- the question
- allowed context
- instructions

It creates the final response.

It does not decide permissions.

---

# Full Request Example

User asks:

"What is our PTO policy?"

Step 1:

Frontend sends the question.

Step 2:

Gateway identifies the user.

Step 3:

Supabase checks:

Company:
Company A

Department:
HR

Role:
Employee

Step 4:

Supabase retrieves allowed documents.

Step 5:

Gateway sends only allowed information to Flowise.

Step 6:

Flowise creates the answer.

Step 7:

Gateway returns the answer.

---

# Security Rules

Rule 1:

A user cannot access another company's information.

---

Rule 2:

A user only receives documents allowed by their role and department.

---

Rule 3:

Flowise only receives approved context, not the entire database.
