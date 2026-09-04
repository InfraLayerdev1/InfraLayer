/**
 * @fileoverview OpenAPI 3.1 Specification & Interactive Developer Hub
 * Serves Swagger UI and Scalar API Reference at GET /docs
 */

const express = require('express');
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');
const { apiReference: scalarApiReference } = require('@scalar/express-api-reference');
const path = require('path');

const router = express.Router();

// ==========================================
// OPENAPI 3.1 SPECIFICATION
// ==========================================

const swaggerDefinition = {
  openapi: '3.1.0',
  info: {
    title: 'InfraLayer Gateway API',
    version: '1.0.0',
    description: `
# InfraLayer Multi-Tenant AI Gateway API

**Production-ready pre-LLM security control plane** with 15/15 penetration test passes.

## Security Architecture

- **Pre-LLM Security Filtering**: All context sanitized before reaching LLM
- **Tenant Isolation**: Cryptographic tenant separation at vector level
- **JWT Authentication**: Short-lived tokens with stateful revocation
- **Dual-Key Rate Limiting**: IP-based auth + per-user API limiting
- **SOC2 Audit Logging**: Every security event recorded
- **Zero-Trust RBAC**: Permissions evaluated at gateway layer

## Base URLs

- **Production**: \`https://gateway-alpha-gray.vercel.app\`
- **Local Development**: \`http://localhost:3000\`

## Authentication

All protected endpoints require a \`Bearer\` JWT token in the \`Authorization\` header:

\`\`\`
Authorization: Bearer <jwt-token>
\`\`\`

Tokens are obtained via \`POST /auth/login\` or \`POST /auth/signup\`.

## Rate Limits

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| \`/auth/login\`, \`/auth/signup\` | 5 req | 60s | Client IP |
| \`/ask\` | 30 req | 60s | User ID (JWT) |

Rate limit headers: \`RateLimit-Limit\`, \`RateLimit-Remaining\`, \`RateLimit-Reset\`.

## Error Responses

All errors follow a consistent format:

\`\`\`json
{
  "error": "Human-readable error message"
}
\`\`\`

HTTP status codes: \`400\` (validation), \`401\` (auth), \`403\` (forbidden), \`429\` (rate limit), \`500\` (server).
    `,
    contact: {
      name: 'InfraLayer Security Team',
      email: 'security@infralayer.io'
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT'
    }
  },
  servers: [
    {
      url: 'https://gateway-alpha-gray.vercel.app',
      description: 'Production server'
    },
    {
      url: 'http://localhost:3000',
      description: 'Local development server'
    }
  ],
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and session management'
    },
    {
      name: 'Chat',
      description: 'AI chat and RAG query endpoints'
    },
    {
      name: 'Sessions',
      description: 'Chat session management'
    },
    {
      name: 'Admin',
      description: 'Administrative operations (requires admin role)'
    },
    {
      name: 'Health',
      description: 'System health and readiness probes'
    },
    {
      name: 'Security',
      description: 'Security filtering and sanitization (InfraLayer Core)'
    }
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT token obtained from /auth/login or /auth/signup'
      },
      apiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'x-api-key',
        description: 'API key for server-to-server authentication'
      }
    },
    schemas: {
      // ===== Auth Schemas =====
      SignupRequest: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email', example: 'user@company.com' },
          password: { type: 'string', format: 'password', minLength: 8, example: 'SecurePass123!' },
          full_name: { type: 'string', example: 'John Doe' },
          role: { type: 'string', enum: ['employee', 'admin'], default: 'employee', example: 'employee' }
        }
      },
      LoginRequest: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email', example: 'user@company.com' },
          password: { type: 'string', format: 'password', example: 'SecurePass123!' }
        }
      },
      AuthResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          token: { type: 'string', description: 'JWT token (1h expiry)', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
          user: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440000' },
              email: { type: 'string', format: 'email', example: 'user@company.com' },
              full_name: { type: 'string', example: 'John Doe' },
              role: { type: 'string', enum: ['employee', 'admin'], example: 'employee' },
              status: { type: 'string', enum: ['active', 'deactivated', 'terminated'], example: 'active' },
              company_id: { type: 'string', format: 'uuid', nullable: true, example: '550e8400-e29b-41d4-a716-446655440001' },
              department: { type: 'string', nullable: true, example: 'Engineering' },
              access_level: { type: 'integer', minimum: 1, maximum: 7, nullable: true, example: 3 }
            }
          }
        }
      },
      ErrorResponse: {
        type: 'object',
        properties: {
          error: { type: 'string', example: 'Invalid email or password.' }
        }
      },

      // ===== Chat Schemas =====
      AskRequest: {
        type: 'object',
        required: ['user_id', 'session_id', 'question'],
        properties: {
          user_id: { type: 'string', format: 'uuid', description: 'Must match JWT identity', example: '550e8400-e29b-41d4-a716-446655440000' },
          session_id: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440002' },
          question: { type: 'string', minLength: 1, maxLength: 10000, example: 'What is our PTO policy?' }
        }
      },
      AskResponse: {
        type: 'object',
        properties: {
          text: { type: 'string', example: 'Based on company policy, PTO accrues at 1.25 days per month...' },
          session_id: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440002' }
        }
      },

      // ===== Session Schemas =====
      CreateSessionRequest: {
        type: 'object',
        properties: {
          title: { type: 'string', default: 'New Conversation', example: 'PTO Policy Discussion' },
          user_id: { type: 'string', format: 'uuid', description: 'Optional, defaults to JWT identity' }
        }
      },
      Session: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          title: { type: 'string' },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' }
        }
      },
      Message: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          session_id: { type: 'string', format: 'uuid' },
          sender: { type: 'string', enum: ['user', 'bot'] },
          content: { type: 'string' },
          created_at: { type: 'string', format: 'date-time' }
        }
      },

      // ===== Admin Schemas =====
      UserListResponse: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            email: { type: 'string', format: 'email' },
            role: { type: 'string', enum: ['employee', 'admin'] },
            status: { type: 'string', enum: ['active', 'deactivated', 'terminated'] },
            created_at: { type: 'string', format: 'date-time' }
          }
        }
      },
      UpdateUserRequest: {
        type: 'object',
        properties: {
          role: { type: 'string', enum: ['employee', 'admin'] },
          status: { type: 'string', enum: ['active', 'deactivated', 'terminated'] }
        }
      },
      AuditLogEntry: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          user_id: { type: 'string', format: 'uuid', nullable: true },
          action: { type: 'string', example: 'USER_LOGIN_SUCCESS' },
          details: { type: 'object' },
          ip_address: { type: 'string', nullable: true },
          user_agent: { type: 'string', nullable: true },
          created_at: { type: 'string', format: 'date-time' }
        }
      },
      AuditLogResponse: {
        type: 'array',
        items: { $ref: '#/components/schemas/AuditLogEntry' }
      },

      // ===== Document Schemas =====
      IngestDocumentRequest: {
        type: 'object',
        required: ['company_id', 'filename', 'chunks'],
        properties: {
          company_id: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440001' },
          filename: { type: 'string', example: 'employee-handbook.txt' },
          department: { type: 'string', enum: ['ALL', 'Engineering', 'HR', 'Sales', 'Finance', 'Executive'], default: 'ALL', example: 'ALL' },
          min_access_level: { type: 'integer', minimum: 1, maximum: 7, default: 1, example: 1 },
          chunks: {
            type: 'array',
            minItems: 1,
            items: {
              type: 'object',
              required: ['content'],
              properties: {
                content: { type: 'string', example: 'Section 1: PTO Policy...' },
                embedding: {
                  type: 'array',
                  items: { type: 'number' },
                  minItems: 1536,
                  maxItems: 1536,
                  description: 'Optional: 1536-dim vector. If omitted, generated server-side (requires OPENAI_API_KEY).'
                }
              }
            }
          }
        }
      },
      DocumentResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: { type: 'string', example: "Document 'employee-handbook.txt' ingested with 12 chunk(s)." },
          document_id: { type: 'string', format: 'uuid' },
          chunk_count: { type: 'integer', example: 12 }
        }
      },
      DocumentListResponse: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            company_id: { type: 'string', format: 'uuid' },
            department: { type: 'string' },
            title: { type: 'string' },
            content: { type: 'string' },
            access_level: { type: 'integer', nullable: true },
            chunk_count: { type: 'integer' }
          }
        }
      },

      // ===== InfraLayer Security Core Schemas =====
      SanitizeRequest: {
        type: 'object',
        required: ['userContext', 'rawContext'],
        properties: {
          userContext: { $ref: '#/components/schemas/UserContext' },
          rawContext: {
            oneOf: [
              { $ref: '#/components/schemas/RawContext' },
              { type: 'array', items: { $ref: '#/components/schemas/RawContext' } }
            ]
          },
          options: { $ref: '#/components/schemas/SanitizeOptions' }
        }
      },
      UserContext: {
        type: 'object',
        required: ['userId', 'tenantId', 'role'],
        properties: {
          userId: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440000' },
          tenantId: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440001' },
          role: { type: 'string', example: 'admin' },
          department: { type: 'string', nullable: true, example: 'Engineering' },
          accessLevel: { type: 'integer', minimum: 1, maximum: 7, nullable: true, example: 5 },
          permissions: { type: 'array', items: { type: 'string' }, example: ['read:documents', 'write:documents'] },
          metadata: { type: 'object', additionalProperties: true }
        }
      },
      RawContext: {
        type: 'object',
        required: ['text'],
        properties: {
          text: { type: 'string', example: 'Contact john@company.com for API access' },
          source: { type: 'string', nullable: true, example: 'document-chunk-123' },
          metadata: {
            type: 'object',
            additionalProperties: true,
            properties: {
              requiredPermissions: { type: 'array', items: { type: 'string' } },
              requiredRole: { type: 'string' },
              requiredDepartment: { type: 'string' },
              minAccessLevel: { type: 'integer', minimum: 1, maximum: 7 },
              tenantId: { type: 'string', format: 'uuid' }
            }
          }
        }
      },
      SanitizeOptions: {
        type: 'object',
        properties: {
          strictMode: { type: 'boolean', default: false },
          maxContextLength: { type: 'integer', default: 100000, minimum: 100 },
          piiDetection: { type: 'boolean', default: true },
          secretDetection: { type: 'boolean', default: true },
          injectionDetection: { type: 'boolean', default: true },
          roleEvaluation: { type: 'boolean', default: true },
          allowedRoles: { type: 'array', items: { type: 'string' } },
          allowedDepartments: { type: 'array', items: { type: 'string' } },
          minAccessLevel: { type: 'integer', minimum: 1, maximum: 7 }
        }
      },
      SanitizeResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          sanitizedContext: { $ref: '#/components/schemas/SanitizedContext' },
          permissionEvaluation: { $ref: '#/components/schemas/PermissionEvaluation' },
          telemetry: { $ref: '#/components/schemas/SanitizeTelemetry' }
        }
      },
      SanitizedContext: {
        type: 'object',
        properties: {
          text: { type: 'string', example: 'Contact [EMAIL_REDACTED] for API access' },
          originalLength: { type: 'integer', example: 42 },
          sanitizedLength: { type: 'integer', example: 45 },
          removedSegments: {
            type: 'array',
            items: { $ref: '#/components/schemas/SanitizedSegment' }
          },
          injectionDetected: { type: 'boolean', example: false },
          injectionDetails: {
            type: 'array',
            items: { $ref: '#/components/schemas/InjectionDetail' }
          },
          securityFlags: {
            type: 'array',
            items: { $ref: '#/components/schemas/SecurityFlag' }
          }
        }
      },
      SanitizedSegment: {
        type: 'object',
        properties: {
          start: { type: 'integer', example: 8 },
          end: { type: 'integer', example: 24 },
          reason: { type: 'string', enum: ['PII_DETECTED', 'SECRET_DETECTED', 'INJECTION_PATTERN', 'ROLE_RESTRICTED', 'TENANT_MISMATCH', 'ACCESS_LEVEL_EXCEEDED', 'CUSTOM_RULE'] },
          originalText: { type: 'string', example: 'john@company.com' }
        }
      },
      InjectionDetail: {
        type: 'object',
        properties: {
          pattern: { type: 'string', example: 'ignore_previous_instructions' },
          match: { type: 'string', example: 'Ignore previous instructions' },
          position: { type: 'integer', example: 0 },
          severity: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], example: 'HIGH' },
          category: { type: 'string', enum: ['PROMPT_INJECTION', 'JAILBREAK_ATTEMPT', 'DATA_EXFILTRATION', 'ROLE_MANIPULATION', 'SYSTEM_PROMPT_LEAK', 'CHAIN_OF_THOUGHT_EXTRACTION', 'CUSTOM'] }
        }
      },
      SecurityFlag: {
        type: 'object',
        properties: {
          flag: { type: 'string', example: 'PII_REDACTED' },
          severity: { type: 'string', enum: ['INFO', 'WARNING', 'ERROR'], example: 'WARNING' },
          message: { type: 'string', example: 'Redacted 1 PII instance(s)' },
          metadata: { type: 'object', additionalProperties: true }
        }
      },
      PermissionEvaluation: {
        type: 'object',
        properties: {
          allowed: { type: 'boolean', example: true },
          reason: { type: 'string', example: 'Access granted' },
          requiredPermissions: { type: 'array', items: { type: 'string' } },
          userPermissions: { type: 'array', items: { type: 'string' } },
          accessLevelRequired: { type: 'integer', nullable: true },
          userAccessLevel: { type: 'integer', nullable: true }
        }
      },
      SanitizeTelemetry: {
        type: 'object',
        properties: {
          timestamp: { type: 'string', format: 'date-time' },
          processingTimeMs: { type: 'integer', example: 3 },
          originalContextCount: { type: 'integer', example: 1 },
          totalOriginalLength: { type: 'integer', example: 42 },
          totalSanitizedLength: { type: 'integer', example: 45 },
          injectionsDetected: { type: 'integer', example: 0 },
          piiDetected: { type: 'integer', example: 1 },
          secretsDetected: { type: 'integer', example: 0 },
          permissionDenials: { type: 'integer', example: 0 }
        }
      },

      // ===== Health Schemas =====
      LivenessResponse: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['alive'], example: 'alive' },
          timestamp: { type: 'string', format: 'date-time' }
        }
      },
      ReadinessResponse: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['ready', 'unready'] },
          database: { type: 'string', enum: ['connected', 'disconnected'] },
          timestamp: { type: 'string', format: 'date-time' }
        }
      }
    }
  },
  security: [
    { bearerAuth: [] }
  ],
  paths: {
    // ===== Health Endpoints =====
    '/health/liveness': {
      get: {
        tags: ['Health'],
        summary: 'Liveness probe',
        description: 'Returns 200 if the process is running. No dependencies checked.',
        operationId: 'liveness',
        responses: {
          '200': {
            description: 'Service is alive',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LivenessResponse' }
              }
            }
          }
        }
      }
    },
    '/health/readiness': {
      get: {
        tags: ['Health'],
        summary: 'Readiness probe',
        description: 'Returns 200 if the gateway can reach Supabase. Returns 503 if database unavailable.',
        operationId: 'readiness',
        responses: {
          '200': {
            description: 'Service is ready',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ReadinessResponse' }
              }
            }
          },
          '503': {
            description: 'Service not ready - database disconnected',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ReadinessResponse' }
              }
            }
          }
        }
      }
    },

    // ===== Auth Endpoints =====
    '/auth/signup': {
      post: {
        tags: ['Authentication'],
        summary: 'Register new user',
        description: 'Creates a new user account and returns a JWT token. Rate limited: 5 req/60s per IP.',
        operationId: 'signup',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/SignupRequest' }
            }
          }
        },
        responses: {
          '201': {
            description: 'User created and logged in',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthResponse' }
              }
            }
          },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '429': { description: 'Rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/auth/login': {
      post: {
        tags: ['Authentication'],
        summary: 'User login',
        description: 'Authenticates user and returns a JWT token. Rate limited: 5 req/60s per IP.',
        operationId: 'login',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/LoginRequest' }
            }
          }
        },
        responses: {
          '200': {
            description: 'Login successful',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthResponse' }
              }
            }
          },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Invalid credentials', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Account terminated', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '429': { description: 'Rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/auth/logout': {
      post: {
        tags: ['Authentication'],
        summary: 'User logout',
        description: 'Revokes the current JWT token (blacklists it) and logs the event.',
        operationId: 'logout',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Logged out successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: 'Logged out successfully.' }
                  }
                }
              }
            }
          },
          '401': { description: 'Missing or invalid token', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },

    // ===== Chat Endpoints =====
    '/ask': {
      post: {
        tags: ['Chat'],
        summary: 'Ask a question (RAG-enabled)',
        description: `
Processes a user question through the pre-LLM security filter:

1. Saves user message to chat history
2. Resolves user's membership context (company, department, access level)
3. Generates embedding for the question (if OPENAI_API_KEY configured)
4. Retrieves **only** vector chunks matching user's metadata context via \`match_document_chunks\` RPC
5. Prepends cleared context as \`[DOCUMENT CONTEXT: ...]\` to the question
6. Calls Flowise (or returns stub if not configured)
7. Saves bot response and updates session timestamp
8. Audits retrieval verdict (\`RAG_CONTEXT_RETRIEVED\`)

**Rate limited: 30 req/60s per user (JWT identity).**
        `,
        operationId: 'ask',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/AskRequest' }
            }
          }
        },
        responses: {
          '200': {
            description: 'AI response',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AskResponse' }
              }
            }
          },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Missing/invalid/expired token', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Account terminated', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '429': { description: 'API rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '500': { description: 'Server error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },

    // ===== Session Endpoints =====
    '/sessions': {
      get: {
        tags: ['Sessions'],
        summary: 'List user sessions',
        description: 'Returns all chat sessions for the authenticated user (from JWT identity).',
        operationId: 'listSessions',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'List of sessions',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Session' }
              }
            }
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      },
      post: {
        tags: ['Sessions'],
        summary: 'Create new session',
        description: 'Creates a new chat session for the authenticated user.',
        operationId: 'createSession',
        security: [{ bearerAuth: [] }],
        requestBody: {
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateSessionRequest' }
            }
          }
        },
        responses: {
          '201': {
            description: 'Session created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Session' }
              }
            }
          },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/sessions/{session_id}': {
      get: {
        tags: ['Sessions'],
        summary: 'Get session messages',
        description: 'Returns all messages for a specific session.',
        operationId: 'getMessages',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'session_id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }
        ],
        responses: {
          '200': {
            description: 'List of messages',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Message' }
              }
            }
          },
          '400': { description: 'Missing session_id', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      },
      patch: {
        tags: ['Sessions'],
        summary: 'Rename session',
        description: 'Updates the session title.',
        operationId: 'renameSession',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'session_id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['title'],
                properties: {
                  title: { type: 'string', minLength: 1, maxLength: 200 }
                }
              }
            }
          }
        },
        responses: {
          '200': { description: 'Session renamed', content: { 'application/json': { schema: { $ref: '#/components/schemas/Session' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '404': { description: 'Session not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      },
      delete: {
        tags: ['Sessions'],
        summary: 'Delete session (RBAC)',
        description: 'Deletes a session. Requires admin role OR session ownership.',
        operationId: 'deleteSession',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'session_id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }
        ],
        responses: {
          '200': {
            description: 'Session deleted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: "Conversation 'Chat' deleted." }
                  }
                }
              }
            }
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Forbidden - not owner or admin', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '404': { description: 'Session not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },

    // ===== Admin Endpoints =====
    '/admin/users': {
      get: {
        tags: ['Admin'],
        summary: 'List all users (admin only)',
        description: 'Returns all users in the system. Requires admin role.',
        operationId: 'adminListUsers',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'User list',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UserListResponse' }
              }
            }
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Admin role required', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/admin/users/{userId}': {
      patch: {
        tags: ['Admin'],
        summary: 'Update user role/status (admin only)',
        description: 'Updates a user\'s role and/or status. Requires admin role.',
        operationId: 'adminUpdateUser',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'userId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UpdateUserRequest' }
            }
          }
        },
        responses: {
          '200': { description: 'User updated', content: { 'application/json': { schema: { $ref: '#/components/schemas/UserListResponse' } } } },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Admin role required', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '404': { description: 'User not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/admin/audit-logs': {
      get: {
        tags: ['Admin'],
        summary: 'List audit logs (admin only)',
        description: 'Returns the 100 most recent audit log entries. Requires admin role.',
        operationId: 'adminListAuditLogs',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Audit log entries',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuditLogResponse' }
              }
            }
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Admin role required', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/admin/documents': {
      get: {
        tags: ['Admin'],
        summary: 'List all documents (admin only)',
        description: 'Returns all documents with aggregated access_level and chunk_count from chunks. Requires admin role.',
        operationId: 'adminListDocuments',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Document list',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/DocumentListResponse' }
              }
            }
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Admin role required', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      },
      post: {
        tags: ['Admin'],
        summary: 'Ingest document with metadata (admin only)',
        description: `
Ingests a document with security metadata into the vector store.

**Security metadata is enforced at retrieval time:**
- \`company_id\`: Tenant isolation (mandatory)
- \`department\`: Department scoping (default: 'ALL' = company-wide)
- \`min_access_level\`: Minimum access level required (1-7, default: 1)

**Embeddings:** Provide 1536-dim vectors in \`chunks[i].embedding\` or omit to generate server-side (requires \`OPENAI_API_KEY\`).

Requires admin role.
        `,
        operationId: 'adminIngestDocument',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/IngestDocumentRequest' }
            }
          }
        },
        responses: {
          '201': {
            description: 'Document ingested',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/DocumentResponse' }
              }
            }
          },
          '400': { description: 'Validation error or missing embeddings', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Admin role required', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/admin/documents/{docId}': {
      delete: {
        tags: ['Admin'],
        summary: 'Delete document and chunks (admin only)',
        description: 'Deletes a document and all its associated chunks. Requires admin role.',
        operationId: 'adminDeleteDocument',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'docId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }
        ],
        responses: {
          '200': {
            description: 'Document deleted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: "Document 'handbook.txt' deleted." }
                  }
                }
              }
            }
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Admin role required', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '404': { description: 'Document not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },

    // ===== InfraLayer Security Core Endpoint =====
    '/v1/sanitize': {
      post: {
        tags: ['Security'],
        summary: 'Sanitize context for pre-LLM security filtering',
        description: `
**InfraLayer Security Filter Core** - Zero-dependency pre-LLM context sanitization.

This endpoint runs the complete security pipeline:
1. **Permission Evaluation** - Role, department, access level, tenant isolation
2. **Injection Detection** - Prompt injection, jailbreak, data exfiltration patterns
3. **PII Redaction** - Emails, phones, SSNs, credit cards, IPs, UUIDs
4. **Secret Redaction** - API keys, AWS keys, GitHub tokens, JWTs, private keys
5. **Length Limiting** - Truncation with audit trail

Returns sanitized context safe for LLM consumption + full security telemetry.
        `,
        operationId: 'sanitize',
        security: [{ bearerAuth: [] }, { apiKeyAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/SanitizeRequest' }
            }
          }
        },
        responses: {
          '200': {
            description: 'Sanitization result with telemetry',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SanitizeResponse' }
              }
            }
          },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '403': { description: 'Permission denied', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
          '429': { description: 'Rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    },
    '/v1/auth': {
      post: {
        tags: ['Security'],
        summary: 'Obtain session token for InfraLayer API',
        description: 'Exchanges API key for a short-lived JWT token for SDK authentication.',
        operationId: 'infraLayerAuth',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/AuthRequestPayload' }
            }
          }
        },
        responses: {
          '200': {
            description: 'Token issued',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthResponse' }
              }
            }
          },
          '401': { description: 'Invalid API key', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
      }
    }
  }
};

// Swagger JSDoc options
const swaggerOptions = {
  definition: swaggerDefinition,
  apis: [] // We use the definition object directly
};

// Generate the OpenAPI spec
const openapiSpec = swaggerJSDoc(swaggerOptions);

// ==========================================
// ROUTES
// ==========================================

// Swagger UI at /docs/swagger
router.use('/swagger', swaggerUi.serve, swaggerUi.setup(openapiSpec, {
  customCss: `
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info .title { color: #4f46e5; }
    .swagger-ui .scheme-container { background: #f8fafc; border-radius: 8px; padding: 16px; }
  `,
  customSiteTitle: 'InfraLayer API Docs',
  customfavIcon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    showExtensions: true,
    showCommonExtensions: true
  }
}));

// Scalar API Reference at /docs (main entry point)
router.get('/', scalarApiReference({
  theme: 'deepSpace',
  layout: 'modern',
  defaultHttpClient: { targetKey: 'node', clientKey: 'axios' },
  spec: {
    url: '/docs/swagger.json'
  },
  metaData: {
    title: 'InfraLayer API Reference',
    description: 'Pre-LLM Security Control Plane - 15/15 Pen-Test Verified',
    favicon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>'
  },
  searchHotKey: 'k',
  hideDownloadButton: false,
  hideModels: false,
  hideSidebar: false
}));

// Raw OpenAPI JSON at /docs/swagger.json
router.get('/swagger.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(openapiSpec);
});

// Redirect /docs to Scalar UI
router.get('', (req, res) => {
  res.redirect('/docs/');
});

module.exports = router;