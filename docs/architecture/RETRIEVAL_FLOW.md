# Retrieval Flow

## User Question

The user sends a question.

Example:

"What is our sales pricing policy?"

The question enters through the frontend.

---

## Identity Check

The system identifies the user.

The Gateway uses the user's UID.

Supabase checks:

- User ID
- Company ID
- Company name
- Role
- Department
- Level

Example:

User:

Company A

Department:
Sales

Role:
Sales Specialist

---

## Permission Filter

Before searching, the system checks:

- Does this user belong to the company?
- Is the user allowed to access this department?
- Does their role have permission to view this information?
- Does their level allow access?

Only approved information continues.

---

## Search

The system searches only allowed knowledge.

Example:

User:

Company A
Sales
Specialist

Search:

Company A documents

Department:
Sales

Permission:
Allowed

The system does not retrieve unrelated departments or companies.

---

## Flowise Input

Gateway sends Flowise only the required information.

Flowise receives:

- User question
- Allowed context
- Instructions

Flowise does not receive the entire database.

---

## Final Answer

Flowise creates the answer.

The Gateway returns the answer to the user.

The user only sees information they are allowed to access.
