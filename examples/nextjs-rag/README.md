# Next.js RAG Example with InfraLayer

A minimal Next.js (App Router) example demonstrating **pre-LLM security filtering** using `@infralayer/sdk`.

## Features

- 🔒 Pre-LLM prompt injection sanitization
- 🛡️ Role-based permission checks before RAG retrieval
- 📊 Telemetry on every request
- ⚡ 3-line integration with `createLocalInfraLayer()`

## Quickstart

```bash
# Install dependencies
npm install

# Run the dev server
npm run dev
```

Navigate to `http://localhost:3000` and ask a question.

## How It Works

1. The user submits a question via the chat UI
2. `POST /api/ask` calls `infra.sanitize({ text }, user)`
3. The security filter checks for injections, validates permissions, and sanitizes PII
4. If blocked, a 403 with `blocked: true` is returned
5. Otherwise the sanitized context is sent to your RAG pipeline + LLM

## Integration Points

- **RAG Retrieval**: Replace the mock answer in `/api/ask/route.ts` with your vector DB call
- **Auth**: Replace the hardcoded user context with your real auth middleware
- **Remote Mode**: Use `createRemoteInfraLayer()` when filtering is centralized in a gateway service

## Stack

- Next.js 14 (App Router)
- TypeScript
- @infralayer/sdk
- Tailwind CSS
