# API Design


POST /chat

Request:

{
 user_id,
 company_id,
 question
}


Process:

1. Validate user
2. Check company
3. Retrieve documents
4. Generate answer
5. Return response


Response:

{
 answer,
 sources,
 timestamp
}
