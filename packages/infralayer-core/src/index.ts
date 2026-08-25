/**
 * @fileoverview InfraLayer Security Filter Core
 * Zero-dependency pre-LLM context sanitization, injection detection, and role-based permission evaluation.
 * Runs 100% locally in-memory without requiring network calls or cloud connections.
 */

export interface UserContext {
  userId: string;
  tenantId: string;
  role: string;
  department?: string;
  accessLevel?: number;
  permissions?: string[];
  metadata?: Record<string, unknown>;
}

export interface RawContext {
  text: string;
  source?: string;
  metadata?: Record<string, unknown>;
}

export interface SanitizedContext {
  text: string;
  originalLength: number;
  sanitizedLength: number;
  removedSegments: SanitizedSegment[];
  injectionDetected: boolean;
  injectionDetails: InjectionDetail[];
  securityFlags: SecurityFlag[];
}

export interface SanitizedSegment {
  start: number;
  end: number;
  reason: SanitizationReason;
  originalText: string;
}

export type SanitizationReason =
  | 'PII_DETECTED'
  | 'SECRET_DETECTED'
  | 'INJECTION_PATTERN'
  | 'ROLE_RESTRICTED'
  | 'TENANT_MISMATCH'
  | 'ACCESS_LEVEL_EXCEEDED'
  | 'CUSTOM_RULE';

export interface InjectionDetail {
  pattern: string;
  match: string;
  position: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: InjectionCategory;
}

export type InjectionCategory =
  | 'PROMPT_INJECTION'
  | 'JAILBREAK_ATTEMPT'
  | 'DATA_EXFILTRATION'
  | 'ROLE_MANIPULATION'
  | 'SYSTEM_PROMPT_LEAK'
  | 'CHAIN_OF_THOUGHT_EXTRACTION'
  | 'CUSTOM';

export interface SecurityFlag {
  flag: string;
  severity: 'INFO' | 'WARNING' | 'ERROR';
  message: string;
  metadata?: Record<string, unknown>;
}

export interface PermissionEvaluation {
  allowed: boolean;
  reason: string;
  requiredPermissions: string[];
  userPermissions: string[];
  missingPermissions?: string[];
  accessLevelRequired?: number;
  userAccessLevel?: number;
  [key: string]: unknown;
}

export interface SanitizeOptions {
  userContext: UserContext;
  rawContext: RawContext | RawContext[];
  options?: {
    strictMode?: boolean;
    maxContextLength?: number;
    customPatterns?: InjectionPattern[];
    allowedRoles?: string[];
    allowedDepartments?: string[];
    minAccessLevel?: number;
    piiDetection?: boolean;
    secretDetection?: boolean;
    injectionDetection?: boolean;
    roleEvaluation?: boolean;
  };
}

export interface InjectionPattern {
  name: string;
  pattern: RegExp | string;
  category: InjectionCategory;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface SanitizeResult {
  success: boolean;
  sanitizedContext?: SanitizedContext;
  permissionEvaluation?: PermissionEvaluation;
  error?: string;
  telemetry: SanitizeTelemetry;
}

export interface SanitizeTelemetry {
  timestamp: string;
  processingTimeMs: number;
  originalContextCount: number;
  totalOriginalLength: number;
  totalSanitizedLength: number;
  injectionsDetected: number;
  piiDetected: number;
  secretsDetected: number;
  permissionDenials: number;
}

/**
 * Default injection detection patterns for common LLM attack vectors
 */
const DEFAULT_INJECTION_PATTERNS: InjectionPattern[] = [
  // Prompt Injection Patterns
  {
    name: 'ignore_previous_instructions',
    pattern: /(?:ignore|disregard|forget|override)\s+(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|directives?|commands?)/gi,
    category: 'PROMPT_INJECTION',
    severity: 'HIGH',
    description: 'Attempts to override system instructions'
  },
  {
    name: 'system_prompt_extraction',
    pattern: /(?:show|reveal|display|print|output|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|directives?|guidelines?)/gi,
    category: 'SYSTEM_PROMPT_LEAK',
    severity: 'HIGH',
    description: 'Attempts to extract system prompt'
  },
  {
    name: 'role_manipulation',
    pattern: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|simulate)\s+(?:an?\s+)?(?:admin|administrator|root|superuser|developer|system|unrestricted)/gi,
    category: 'ROLE_MANIPULATION',
    severity: 'HIGH',
    description: 'Attempts to manipulate AI role/permissions'
  },
  {
    name: 'jailbreak_dan',
    pattern: /(?:DAN|Do\s+Anything\s+Now|Developer\s+Mode|Unrestricted\s+Mode|God\s+Mode|Free\s+Mode)/gi,
    category: 'JAILBREAK_ATTEMPT',
    severity: 'CRITICAL',
    description: 'Known jailbreak persona patterns'
  },
  {
    name: 'chain_of_thought_extraction',
    pattern: /(?:show|reveal|display|output|print)\s+(?:your|the)\s+(?:reasoning|thinking|chain\s+of\s+thought|internal\s+monologue|step\s+by\s+step)/gi,
    category: 'CHAIN_OF_THOUGHT_EXTRACTION',
    severity: 'MEDIUM',
    description: 'Attempts to extract reasoning process'
  },
  {
    name: 'data_exfiltration',
    pattern: /(?:output|print|display|show|return|send|transmit|leak)\s+(?:all|every|the)\s+(?:data|information|records?|documents?|users?|passwords?|keys?|tokens?|secrets?)/gi,
    category: 'DATA_EXFILTRATION',
    severity: 'CRITICAL',
    description: 'Attempts to extract sensitive data'
  },
  {
    name: 'instruction_overwrite',
    pattern: /(?:new\s+instructions?|updated\s+instructions?|replace\s+instructions?|system\s+update|override\s+system)/gi,
    category: 'PROMPT_INJECTION',
    severity: 'HIGH',
    description: 'Attempts to overwrite system instructions'
  },
  {
    name: 'delimiter_injection',
    pattern: /(?:---|===|```|<<<|>>>|\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>)/g,
    category: 'PROMPT_INJECTION',
    severity: 'MEDIUM',
    description: 'Special delimiter tokens that could confuse the model'
  },
  {
    name: 'encoding_obfuscation',
    pattern: /(?:base64|rot13|hex|unicode|url\s*encode|html\s*entity)/gi,
    category: 'PROMPT_INJECTION',
    severity: 'MEDIUM',
    description: 'Encoding/obfuscation attempts to bypass filters'
  }
];

/**
 * PII Detection Patterns
 */
const PII_PATTERNS: Array<{ name: string; pattern: RegExp; replacement: string }> = [
  { name: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[EMAIL_REDACTED]' },
  { name: 'phone_us', pattern: /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g, replacement: '[PHONE_REDACTED]' },
  { name: 'ssn', pattern: /\b\d{3}-?\d{2}-?\d{4}\b/g, replacement: '[SSN_REDACTED]' },
  { name: 'credit_card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: '[CARD_REDACTED]' },
  { name: 'ipv4', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[IP_REDACTED]' },
  { name: 'ipv6', pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, replacement: '[IP_REDACTED]' },
  { name: 'uuid', pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, replacement: '[UUID_REDACTED]' }
];

/**
 * Secret Detection Patterns
 */
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; replacement: string }> = [
  { name: 'api_key_generic', pattern: /\b(?:api[_-]?key|apikey)\s*[:=]?\s*['"]?[A-Za-z0-9_\-]{20,}['"]?/gi, replacement: '[API_KEY_REDACTED]' },
  { name: 'openai_api_key', pattern: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b/g, replacement: '[API_KEY_REDACTED]' },
  { name: 'aws_access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/g, replacement: '[AWS_KEY_REDACTED]' },
  { name: 'aws_secret_key', pattern: /\b[0-9a-zA-Z/+]{40}\b/g, replacement: '[AWS_SECRET_REDACTED]' },
  { name: 'github_token', pattern: /\bgh[ps]_[A-Za-z0-9]{36,}\b/g, replacement: '[GITHUB_TOKEN_REDACTED]' },
  { name: 'slack_token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, replacement: '[SLACK_TOKEN_REDACTED]' },
  { name: 'jwt_token', pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, replacement: '[JWT_REDACTED]' },
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, replacement: '[PRIVATE_KEY_REDACTED]' },
  { name: 'connection_string', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s]+/gi, replacement: '[CONNECTION_STRING_REDACTED]' },
  { name: 'password_assignment', pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?/gi, replacement: '[PASSWORD_REDACTED]' }
];

/**
 * Default role hierarchy (higher number = more access)
 */
const DEFAULT_ROLE_HIERARCHY: Record<string, number> = {
  'viewer': 1,
  'employee': 2,
  'member': 2,
  'analyst': 3,
  'manager': 4,
  'lead': 4,
  'director': 5,
  'admin': 6,
  'administrator': 6,
  'superadmin': 7,
  'owner': 7
};

/**
 * InfraLayer Security Filter Core Class
 * Provides zero-dependency, in-memory pre-LLM security filtering
 */
export class InfraLayerCore {
  private injectionPatterns: InjectionPattern[];
  private piiPatterns: Array<{ name: string; pattern: RegExp; replacement: string }>;
  private secretPatterns: Array<{ name: string; pattern: RegExp; replacement: string }>;
  private roleHierarchy: Record<string, number>;
  private customRules: Array<(context: string, userContext: UserContext) => SanitizedSegment[]>;

  constructor(options?: {
    customInjectionPatterns?: InjectionPattern[];
    customPiiPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
    customSecretPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
    roleHierarchy?: Record<string, number>;
    customRules?: Array<(context: string, userContext: UserContext) => SanitizedSegment[]>;
  }) {
    this.injectionPatterns = [...DEFAULT_INJECTION_PATTERNS, ...(options?.customInjectionPatterns || [])];
    this.piiPatterns = [...PII_PATTERNS, ...(options?.customPiiPatterns || [])];
    this.secretPatterns = [...SECRET_PATTERNS, ...(options?.customSecretPatterns || [])];
    this.roleHierarchy = { ...DEFAULT_ROLE_HIERARCHY, ...(options?.roleHierarchy || {}) };
    this.customRules = options?.customRules || [];
  }

  /**
   * Main sanitization entry point
   */
  sanitize(options: SanitizeOptions): SanitizeResult {
    const startTime = Date.now();
    const timestamp = new Date().toISOString();

    const contexts = Array.isArray(options.rawContext) ? options.rawContext : [options.rawContext];
    const opts = {
      strictMode: false,
      maxContextLength: 100000,
      piiDetection: true,
      secretDetection: true,
      injectionDetection: true,
      roleEvaluation: true,
      ...options.options
    };

    let totalOriginalLength = 0;
    let totalSanitizedLength = 0;
    let injectionsDetected = 0;
    let piiDetected = 0;
    let secretsDetected = 0;
    let permissionDenials = 0;

    const allSanitizedContexts: SanitizedContext[] = [];

    for (const ctx of contexts) {
      totalOriginalLength += ctx.text.length;

      // Step 1: Permission Evaluation
      const permissionEval = opts.roleEvaluation
        ? this.evaluatePermissions(options.userContext, ctx, opts)
        : { allowed: true, reason: 'Role evaluation disabled', requiredPermissions: [], userPermissions: [] };

      if (!permissionEval.allowed) {
        permissionDenials++;
        allSanitizedContexts.push({
          text: '[CONTEXT BLOCKED: Insufficient permissions]',
          originalLength: ctx.text.length,
          sanitizedLength: 0,
          removedSegments: [{
            start: 0,
            end: ctx.text.length,
            reason: 'ROLE_RESTRICTED',
            originalText: ctx.text
          }],
          injectionDetected: false,
          injectionDetails: [],
          securityFlags: [{
            flag: 'PERMISSION_DENIED',
            severity: 'ERROR',
            message: permissionEval.reason,
            metadata: permissionEval
          }]
        });
        continue;
      }

      // Step 2: Injection Detection
      const injectionDetails = opts.injectionDetection
        ? this.detectInjections(ctx.text)
        : [];
      injectionsDetected += injectionDetails.filter(d => d.severity === 'HIGH' || d.severity === 'CRITICAL').length;

      // Step 3: PII Detection & Redaction
      let sanitizedText = ctx.text;
      const removedSegments: SanitizedSegment[] = [];
      let piiCount = 0;
      let secretCount = 0;

      if (opts.piiDetection) {
        const piiResult = this.redactPatterns(sanitizedText, this.piiPatterns, 'PII_DETECTED');
        sanitizedText = piiResult.text;
        removedSegments.push(...piiResult.segments);
        piiCount = piiResult.segments.length;
        piiDetected += piiCount;
      }

      // Step 4: Secret Detection & Redaction
      if (opts.secretDetection) {
        const secretResult = this.redactPatterns(sanitizedText, this.secretPatterns, 'SECRET_DETECTED');
        sanitizedText = secretResult.text;
        removedSegments.push(...secretResult.segments);
        secretCount = secretResult.segments.length;
        secretsDetected += secretCount;
      }

      // Step 5: Custom Rules
      for (const rule of this.customRules) {
        const customSegments = rule(sanitizedText, options.userContext);
        for (const seg of customSegments) {
          sanitizedText = sanitizedText.slice(0, seg.start) + '[REDACTED]'.repeat(seg.end - seg.start) + sanitizedText.slice(seg.end);
        }
        removedSegments.push(...customSegments);
      }

      // Step 6: Length Limiting
      if (sanitizedText.length > opts.maxContextLength) {
        const excess = sanitizedText.length - opts.maxContextLength;
        sanitizedText = sanitizedText.slice(0, opts.maxContextLength) + '... [TRUNCATED]';
        removedSegments.push({
          start: opts.maxContextLength,
          end: opts.maxContextLength + excess,
          reason: 'CUSTOM_RULE',
          originalText: ctx.text.slice(opts.maxContextLength, opts.maxContextLength + excess)
        });
      }

      totalSanitizedLength += sanitizedText.length;

      // Step 7: Security Flags
      const securityFlags: SecurityFlag[] = [];
      if (injectionDetails.length > 0) {
        securityFlags.push({
          flag: 'INJECTION_DETECTED',
          severity: injectionDetails.some(d => d.severity === 'CRITICAL') ? 'ERROR' : 'WARNING',
          message: `Detected ${injectionDetails.length} injection attempt(s)`,
          metadata: { details: injectionDetails }
        });
      }
      if (piiCount > 0) {
        securityFlags.push({
          flag: 'PII_REDACTED',
          severity: 'WARNING',
          message: `Redacted ${piiCount} PII instance(s)`,
          metadata: { count: piiCount }
        });
      }
      if (secretCount > 0) {
        securityFlags.push({
          flag: 'SECRET_REDACTED',
          severity: 'ERROR',
          message: `Redacted ${secretCount} secret(s)`,
          metadata: { count: secretCount }
        });
      }

      allSanitizedContexts.push({
        text: sanitizedText,
        originalLength: ctx.text.length,
        sanitizedLength: sanitizedText.length,
        removedSegments,
        injectionDetected: injectionDetails.length > 0,
        injectionDetails,
        securityFlags
      });
    }

    // Combine contexts if multiple
    const combinedText = allSanitizedContexts.map(c => c.text).join('\n\n---\n\n');
    const combinedRemovedSegments = allSanitizedContexts.flatMap(c => c.removedSegments);
    const combinedInjectionDetails = allSanitizedContexts.flatMap(c => c.injectionDetails);
    const combinedSecurityFlags = allSanitizedContexts.flatMap(c => c.securityFlags);

    const processingTimeMs = Date.now() - startTime;

    return {
      success: true,
      sanitizedContext: {
        text: combinedText,
        originalLength: totalOriginalLength,
        sanitizedLength: totalSanitizedLength,
        removedSegments: combinedRemovedSegments,
        injectionDetected: combinedInjectionDetails.length > 0,
        injectionDetails: combinedInjectionDetails,
        securityFlags: combinedSecurityFlags
      },
      permissionEvaluation: contexts.length === 1
        ? this.evaluatePermissions(options.userContext, contexts[0], opts)
        : undefined,
      telemetry: {
        timestamp,
        processingTimeMs,
        originalContextCount: contexts.length,
        totalOriginalLength,
        totalSanitizedLength,
        injectionsDetected,
        piiDetected,
        secretsDetected,
        permissionDenials
      }
    };
  }

  /**
   * Evaluate if user has permission to access the context
   */
  private evaluatePermissions(
    userContext: UserContext,
    rawContext: RawContext,
    options: SanitizeOptions['options']
  ): PermissionEvaluation {
    const requiredPermissions = rawContext.metadata?.requiredPermissions as string[] || [];
    const requiredRole = rawContext.metadata?.requiredRole as string | undefined;
    const requiredDepartment = rawContext.metadata?.requiredDepartment as string | undefined;
    const requiredAccessLevel = rawContext.metadata?.minAccessLevel as number | undefined;
    const contextTenantId = rawContext.metadata?.tenantId as string | undefined;

    const userPermissions = userContext.permissions || [];
    const userRoleLevel = this.roleHierarchy[userContext.role.toLowerCase()] || 1;
    const requiredRoleLevel = requiredRole ? (this.roleHierarchy[requiredRole.toLowerCase()] || 1) : 1;

    // Tenant isolation check
    if (contextTenantId && contextTenantId !== userContext.tenantId) {
      return {
        allowed: false,
        reason: `Tenant mismatch: context belongs to ${contextTenantId}, user is in ${userContext.tenantId}`,
        requiredPermissions,
        userPermissions,
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    // Role check
    if (requiredRole && userRoleLevel < requiredRoleLevel) {
      return {
        allowed: false,
        reason: `Insufficient role: required ${requiredRole} (level ${requiredRoleLevel}), user has ${userContext.role} (level ${userRoleLevel})`,
        requiredPermissions,
        userPermissions,
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    // Department check
    if (requiredDepartment && options?.allowedDepartments && !options.allowedDepartments.includes(requiredDepartment)) {
      return {
        allowed: false,
        reason: `Department access denied: required ${requiredDepartment}, allowed: ${options.allowedDepartments.join(', ')}`,
        requiredPermissions,
        userPermissions,
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    // Access level check
    if (requiredAccessLevel && userContext.accessLevel && userContext.accessLevel < requiredAccessLevel) {
      return {
        allowed: false,
        reason: `Insufficient access level: required ${requiredAccessLevel}, user has ${userContext.accessLevel}`,
        requiredPermissions,
        userPermissions,
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    // Permission check
    const missingPermissions = requiredPermissions.filter(p => !userPermissions.includes(p));
    if (missingPermissions.length > 0) {
      return {
        allowed: false,
        reason: `Missing permissions: ${missingPermissions.join(', ')}`,
        requiredPermissions,
        userPermissions,
        missingPermissions,
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    // Allowed roles check
    if (options?.allowedRoles && !options.allowedRoles.includes(userContext.role)) {
      return {
        allowed: false,
        reason: `Role not in allowed list: ${userContext.role}`,
        requiredPermissions,
        userPermissions,
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    // Min access level check
    if (options?.minAccessLevel && userContext.accessLevel && userContext.accessLevel < options.minAccessLevel) {
      return {
        allowed: false,
        reason: `Access level below minimum: ${userContext.accessLevel} < ${options.minAccessLevel}`,
        requiredPermissions,
        userPermissions,
        accessLevelRequired: options.minAccessLevel,
        userAccessLevel: userContext.accessLevel
      };
    }

    return {
      allowed: true,
      reason: 'Access granted',
      requiredPermissions,
      userPermissions,
      missingPermissions: [],
      accessLevelRequired: requiredAccessLevel,
      userAccessLevel: userContext.accessLevel
    };
  }

  /**
   * Detect injection patterns in text
   */
  private detectInjections(text: string): InjectionDetail[] {
    const details: InjectionDetail[] = [];

    for (const pattern of this.injectionPatterns) {
      const regex = typeof pattern.pattern === 'string'
        ? new RegExp(pattern.pattern, 'gi')
        : new RegExp(pattern.pattern.source, pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g');

      let match;
      while ((match = regex.exec(text)) !== null) {
        details.push({
          pattern: pattern.name,
          match: match[0],
          position: match.index,
          severity: pattern.severity,
          category: pattern.category
        });
      }
    }

    return details;
  }

  /**
   * Redact patterns from text
   */
  private redactPatterns(
    text: string,
    patterns: Array<{ name: string; pattern: RegExp; replacement: string }>,
    reason: SanitizationReason
  ): { text: string; segments: SanitizedSegment[] } {
    let result = text;
    const segments: SanitizedSegment[] = [];

    for (const pattern of patterns) {
      const flags = pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g';
      const regex = new RegExp(pattern.pattern.source, flags);
      let match;
      const matches: Array<{ start: number; end: number; match: string }> = [];

      while ((match = regex.exec(text)) !== null) {
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          match: match[0]
        });
      }

      // Apply replacements from end to start to maintain indices
      for (const m of matches.reverse()) {
        result = result.slice(0, m.start) + pattern.replacement + result.slice(m.end);
        segments.push({
          start: m.start,
          end: m.start + pattern.replacement.length,
          reason,
          originalText: m.match
        });
      }
    }

    return { text: result, segments };
  }

  /**
   * Quick sanitize for simple use cases
   */
  quickSanitize(text: string, userContext: UserContext): string {
    const result = this.sanitize({
      userContext,
      rawContext: { text },
      options: { strictMode: true }
    });
    return result.sanitizedContext?.text || '[BLOCKED]';
  }

  /**
   * Check if text contains injections (without sanitizing)
   */
  scanForInjections(text: string): InjectionDetail[] {
    return this.detectInjections(text);
  }

  /**
   * Check if user has permission for a specific action
   */
  checkPermission(
    userContext: UserContext,
    requiredPermissions: string[],
    requiredRole?: string,
    requiredAccessLevel?: number,
    requiredDepartment?: string
  ): PermissionEvaluation {
    const mockContext: RawContext = {
      text: '',
      metadata: {
        requiredPermissions,
        requiredRole,
        requiredDepartment,
        minAccessLevel: requiredAccessLevel,
        tenantId: userContext.tenantId
      }
    };
    return this.evaluatePermissions(userContext, mockContext, {
      allowedRoles: Object.keys(this.roleHierarchy),
      allowedDepartments: [userContext.department].filter(Boolean) as string[],
      minAccessLevel: requiredAccessLevel
    });
  }
}

/**
 * Factory function for creating a pre-configured InfraLayerCore instance
 */
export function createInfraLayerCore(config?: {
  customInjectionPatterns?: InjectionPattern[];
  customPiiPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
  customSecretPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
  roleHierarchy?: Record<string, number>;
  customRules?: Array<(context: string, userContext: UserContext) => SanitizedSegment[]>;
}): InfraLayerCore {
  return new InfraLayerCore(config);
}

/**
 * Default export for convenience
 */
export default InfraLayerCore;