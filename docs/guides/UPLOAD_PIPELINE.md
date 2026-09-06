# Upload Pipeline

## Goal

When a user uploads a document,
the system must automatically attach:

- owner
- company
- department
- permissions

before AI can use it.

---

## Upload Start

A user selects a file.

Example:

HR_policy.pdf

HR employees upload it.

See it from their UID, CID, then their role on the company, also their role in the company as an HR

---

## Gateway

Gateway must recieve information about:

UID:
abc245

Company:
Company K

Role & Departement:
HR, HR departement
---

## Processing

Before storing the document need to be attached with:

CID:
GFG123

Departement:
HR Departement

Access:
HR Generalist
---

## Storage

Saved on Company K's private GDrive

SupaBase only store anything on what's inside the GDrive of Company K in format of:
-  PDF
-  TXT
- DOCS

---

## AI Retrieval

The system find the document from what SupaBase have already been provided from their own filtering system.

---

## Result

The only provided answers with that only certain context reached to Flowise.
