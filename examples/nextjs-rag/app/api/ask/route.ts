import { NextRequest, NextResponse } from 'next/server';
import { createLocalInfraLayer, UserContext } from '@infralayer-ai/sdk';

const infra = createLocalInfraLayer();

interface QuestionRequest {
  question: string;
  userId: string;
  tenantId: string;
  role?: string;
  permissions?: string[];
}

export async function POST(request: NextRequest) {
  try {
    const body: QuestionRequest = await request.json();

    const user: UserContext = {
      userId: body.userId,
      tenantId: body.tenantId,
      role: body.role || 'employee',
      permissions: body.permissions || ['read:documents'],
    };

    // Sanitize and check permissions before RAG retrieval
    const result = await infra.sanitize(
      { text: body.question },
      user
    );

    // Check if sanitization failed or was blocked
    if (!result.success || result.permissionEvaluation?.allowed === false) {
      return NextResponse.json({
        answer: result.error || '[BLOCKED] Your request was blocked by security policy.',
        blocked: true,
        telemetry: result.telemetry,
      }, { status: 403 });
    }

    // In a real app, you would now:
    // 1. Use result.sanitizedContext.text for RAG retrieval
    // 2. Call your vector database with filtered context
    // 3. Send to LLM with the sanitized context
    // 4. Return the LLM response

    const mockAnswer = `Based on your company's knowledge base: ${result.sanitizedContext?.text}`;

    return NextResponse.json({
      answer: mockAnswer,
      blocked: false,
      telemetry: result.telemetry,
    });

  } catch (error) {
    console.error('API Error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
