# Gateway Flow


## Purpose


Gateway is the control layer between the user and AI

It decides:

- Who is asking
- What they can access
- What information reaches AI


----


## Incoming Request

The user sends:

Question:
"What is out pricing?"

Gateway receives the question.


-----


## Identity

Gateway gets:

- user_id
- company
- role
- departement

The user identity comes from authentication.


----


## Permission Check

Gateway asks Supabase:

"Is this user allowed to access this information?"


Supabase checks:

- company
- department
- permissions


-----


## Context Retrieval

If allowed:

Gateway retrieves only approved information.

Example:

Company A
Sales
Pricing documents

---


## AI Request

Gateway send Flowise:

- question
- allowed context
- instructions

Flowise creates the answer


----


## Response

Gateway returns the answer to the user.
