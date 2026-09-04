# Vector Database Design

Each chunk needs:

id

company_id

document_id

content

embedding


Example:

Chunk:
"Employees receive 20 PTO days"

company_id:
company_a


The retriever filters:

company_id = current user company

