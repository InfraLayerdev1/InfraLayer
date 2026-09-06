# FastAPI RAG Example with InfraLayer

A minimal FastAPI example demonstrating **pre-LLM security filtering** using the `infralayer` Python SDK.

## Features

- 🔒 Pre-LLM prompt injection sanitization
- 🛡️ Role-based permission checks before RAG retrieval
- 📊 Telemetry on every request
- ⚡ 3-line integration with `create_local_infralayer()`

## Quickstart

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

Navigate to `http://localhost:8000/docs` for the interactive Swagger UI.

## How It Works

1. The user submits a question via `POST /api/ask`
2. The endpoint calls `await infra.sanitize({ "text": question }, user)`
3. The security filter checks for injections, validates permissions, and sanitizes PII
4. If blocked, a 403 with `blocked: true` is returned
5. Otherwise the sanitized context is sent to your RAG pipeline + LLM

## Integration Points

- **RAG Retrieval**: Replace the mock answer in `main.py` with your vector DB call
- **Auth**: Replace `get_current_user` dependency with your real auth middleware
- **Remote Mode**: Use `create_remote_infralayer()` when filtering is centralized in a gateway service

## Stack

- FastAPI 0.110+
- Uvicorn
- Pydantic v2
- infralayer Python SDK
