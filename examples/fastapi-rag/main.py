"""
FastAPI RAG Example with InfraLayer Python SDK
================================================
A minimal example showing how to integrate InfraLayer security filtering
into a FastAPI RAG application.
"""

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from infralayer import create_local_infralayer, UserContext


app = FastAPI(title="FastAPI RAG with InfraLayer")


class QuestionRequest(BaseModel):
    question: str
    user_id: str
    tenant_id: str
    role: str = "employee"
    permissions: list[str] = ["read:documents"]


class QuestionResponse(BaseModel):
    answer: str
    blocked: bool
    telemetry: dict


# Initialize InfraLayer client
infra = create_local_infralayer()


async def get_current_user(request: QuestionRequest) -> InfraLayerUser:
    """Extract user context from request (in real app, from auth middleware)."""
    return InfraLayerUser(
        user_id=request.user_id,
        tenant_id=request.tenant_id,
        role=request.role,
        permissions=request.permissions,
    )


@app.post("/api/ask", response_model=QuestionResponse)
async def ask_question(
    request: QuestionRequest,
    user: InfraLayerUser = Depends(get_current_user),
):
    """
    Process a question through InfraLayer security filtering before
    sending to your RAG pipeline / LLM.
    """
    try:
        # Sanitize and check permissions before RAG retrieval
        result = await infra.sanitize(
            context={"text": request.question},
            user=user,
        )

        if result.blocked:
            return QuestionResponse(
                answer="[BLOCKED] Your request was blocked by security policy.",
                blocked=True,
                telemetry=result.telemetry.model_dump(),
            )

        # In a real app, you would now:
        # 1. Use result.sanitized_context.text for RAG retrieval
        # 2. Call your vector database with filtered context
        # 3. Send to LLM with the sanitized context
        # 4. Return the LLM response

        # For demo, we'll return a mock response
        mock_answer = f"Based on your company's knowledge base: {result.sanitized_context.text}"

        return QuestionResponse(
            answer=mock_answer,
            blocked=False,
            telemetry=result.telemetry.model_dump(),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    """Health check endpoint."""
    health_result = await infra.health_check()
    return health_result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
