# Document Ownership Flow

## Upload

A user uploads a document.

The system identifies:

- uploader
- company
- department
- role

The uploaded file receives ownership information.

---

## Document Identity

A document is not only text.

It also has metadata:

- company_id
- department
- access rules

Metadata protects the document.

---

## Permission Check

Before AI retrieval:

The system checks:

- user identity
- company
- role
- department

Only allowed documents continue.

---

## AI Usage

Flowise receives:

- question
- allowed context
- instructions

Flowise does not decide permissions.

---

## Final Answer

The generated answer returns through Gateway to the user.
