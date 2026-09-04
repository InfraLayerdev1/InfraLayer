# Database Design

## Users Table

Question:

Who is this person?

Stores:

- uid
- name
- email

Purpose:

Identify the user.

---

## Companies Table

Question:

Who owns the information?

Stores:

- company_id
- company_name

Purpose:

Separate organizations.

---

## Memberships Table

Question:

What is the relationship between a person and company?

Stores:

- user_id
- company_id
- role
- department
- level

Purpose:

Decide what the user should access.

---

## Documents Table

Question:

What knowledge exists and who owns it?

Stores:

- document_id
- company_id
- department
- required_permission
- content
- embedding

Purpose:

Allow AI retrieval while protecting company data.

---

# Request Flow

User asks question.

Gateway receives request.

Gateway identifies user.

Supabase checks:

- user
- company
- role
- permissions

Supabase returns allowed knowledge.

Gateway sends:

- question
- allowed context
- instructions

to Flowise.

Flowise creates the answer.

Gateway returns answer to user.

