# Access Control

Rules:

User logs in.

System gets company_id.

Every request includes company_id.

Retrieval only searches:

documents
WHERE company_id = user's company_id


Never allow:
User A -> Company B documents

