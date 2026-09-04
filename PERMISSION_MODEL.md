# Permission Model

## Goal

The system must ensure every user only receives information they are allowed to access.

The AI should never decide permissions.
The system decides permissions before sending information to the AI.

---

# Users

Purpose:

Store identity of the person.

Example fields:

- uid
- name
- email

The user represents the person.

The user does not directly decide access.

---

# Companies

Purpose:

Store organizations.

Example fields:

- company_id
- company_name

A company owns:

- documents
- users
- settings

Company data must be separated.

---

# Membership

Purpose:

Connect a user to a company.

Example fields:

- user_id
- company_id
- role
- department
- level

Example:

User:
John

Company:
Company A

Role:
Sales Representative

Department:
Sales

Level:
Junior


Membership determines the user's relationship with the company.

---

# Permissions

Purpose:

Control what the user can access.

Examples:

- view_sales_documents
- view_finance_documents
- manage_users

Permissions prevent users from seeing information outside their responsibility.

---

# Documents

Purpose:

Store company knowledge.

Example fields:

- document_id
- company_id
- department
- required_permission
- content

Documents must contain ownership information.

The system checks:

Can this user access this document?

before sending it to the AI.

