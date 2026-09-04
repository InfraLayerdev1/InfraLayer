# Tenant Aware RAG

Normal RAG:

Question
↓
Search all documents
↓
AI answer


SaaS RAG:

User question
↓
Get user company_id
↓
Search documents where company_id matches
↓
Send only allowed context
↓
AI answer


Security rule:

AI never receives another company's data.

