/**
 * @fileoverview InfraLayer Security Filter Core
 * Zero-dependency pre-LLM context sanitization, injection detection, and role-based permission evaluation.
 * Runs 100% locally in-memory without requiring network calls or cloud connections.
 */

import { SystemOwnerControl } from './owner-control';

export {
  SystemOwnerControl,
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_MIN_CONCURRENCY,
} from './owner-control';
export type {
  OwnerAction,
  OwnerControlState,
  OwnerOverrideResult,
  OwnerAdmission,
  SystemOwnerControlOptions,
} from './owner-control';

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
  /**
   * Raw `X-InfraLayer-Owner-Override` header value. When a valid System Owner
   * master signature is present it is evaluated BEFORE any context or metadata
   * processing; an invalid/absent header is treated as ordinary unprivileged
   * traffic. Optional — standard callers omit it entirely.
   */
  ownerOverride?: string;
  /**
   * Raw `X-InfraLayer-Owner-Identity` claim. When the master key is bound to a
   * sole named owner (default "Evan Alvino"), the override is applied only if
   * this identity matches that name AND the signature is valid.
   */
  ownerOverrideIdentity?: string;
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
 * Maximum entries retained in telemetry arrays per request to bound memory usage.
 */
const TELEMETRY_MAX_ENTRIES = 50;

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
  private ownerControl: SystemOwnerControl;

  constructor(options?: {
    customInjectionPatterns?: InjectionPattern[];
    customPiiPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
    customSecretPatterns?: Array<{ name: string; pattern: RegExp; replacement: string }>;
    roleHierarchy?: Record<string, number>;
    customRules?: Array<(context: string, userContext: UserContext) => SanitizedSegment[]>;
    ownerControl?: SystemOwnerControl;
  }) {
    this.injectionPatterns = [...DEFAULT_INJECTION_PATTERNS, ...(options?.customInjectionPatterns || [])];
    this.piiPatterns = [...PII_PATTERNS, ...(options?.customPiiPatterns || [])];
    this.secretPatterns = [...SECRET_PATTERNS, ...(options?.customSecretPatterns || [])];
    this.roleHierarchy = { ...DEFAULT_ROLE_HIERARCHY, ...(options?.roleHierarchy || {}) };
    this.customRules = options?.customRules || [];
    this.ownerControl = options?.ownerControl ?? new SystemOwnerControl();
  }

  /**
   * Accessor for the attached System Owner Control engine. A default instance
   * (no master key configured, full 40,000 req/s throughput) is created when
   * none was supplied to the constructor.
   */
  getOwnerControl(): SystemOwnerControl {
    return this.ownerControl;
  }

  /**
   * Pre-normalize input text: strip null bytes, control characters,
   * zero-width spaces, non-breaking spaces, and apply Unicode NFC.
   * Produces a clean evaluation buffer for all downstream scanning.
   */
  private normalizeInput(text: string): string {
    let result = text;
    // Strip null bytes ( )
    result = result.replace(/\0/g, '');
    // Strip control characters (\x00-\x1F) except newline and tab
    result = result.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
    // Strip zero-width spaces (​-‍)
    result = result.replace(/[​-‍]/g, '');
    // Strip non-breaking spaces ( ) — replace with normal space
    result = result.replace(/ /g, ' ');
    // Decode common URI/hex escapes that attackers use to bypass filters
    result = result.replace(/\\u([0-9a-fA-F]{4})/gi, (_m, hex) => String.fromCharCode(parseInt(hex, 16)));
    result = result.replace(/\\x([0-9a-fA-F]{2})/gi, (_m, hex) => String.fromCharCode(parseInt(hex, 16)));
    // Unicode NFC normalization
    result = result.normalize('NFC');
    return result;
  }

  /**
   * Sort segments by start index descending and merge overlapping/adjacent ranges.
   * Returns a new array — never mutates the input.
   */
  private sortAndMergeSegments(segments: SanitizedSegment[]): SanitizedSegment[] {
    if (segments.length === 0) return [];
    // Filter out invalid segments first
    const valid = segments.filter(s => s.end > s.start);
    if (valid.length === 0) return [];
    // Sort ascending by start
    const sorted = [...valid].sort((a, b) => a.start - b.start);
    // Merge overlapping/adjacent
    const merged: SanitizedSegment[] = [];
    let current = { ...sorted[0] };
    for (let i = 1; i < sorted.length; i++) {
      const next = sorted[i];
      if (next.start <= current.end) {
        // Overlapping or adjacent — extend current
        current = {
          start: current.start,
          end: Math.max(current.end, next.end),
          reason: current.reason,
          originalText: current.originalText + next.originalText,
        };
      } else {
        merged.push(current);
        current = { ...next };
      }
    }
    merged.push(current);
    return merged;
  }

  /**
   * Main sanitization entry point
   */
  sanitize(options: SanitizeOptions): SanitizeResult {
    const startTime = Date.now();
    const timestamp = new Date().toISOString();

    // ----------------------------------------------------------------------
    // Step 0: System Owner Control — the very first check, before ANY context
    // or metadata processing. A valid master signature+identity engages the
    // kill-switch (LOCKDOWN), the throughput governor (THROTTLE), or the
    // emergency cache purge (CACHE_PURGE). Any invalid/non-master header is
    // ignored here and the request proceeds as ordinary unprivileged traffic.
    // ----------------------------------------------------------------------
    const ownerResult = this.ownerControl.evaluateOverride(options.ownerOverride, options.ownerOverrideIdentity);
    if (ownerResult.lockDown) {
      return this.buildOwnerControlResult(ownerResult.message, 'SYSTEM_LOCKDOWN', startTime, timestamp, options);
    }

    const admission = this.ownerControl.admissionCheck();
    if (!admission.allowed) {
      return this.buildOwnerControlResult(
        admission.reason === 'THROTTLE_CAPACITY_EXCEEDED'
          ? `System throttled: capacity ${admission.maxConcurrency} req/s reached (active ${admission.activeConcurrency})`
          : ownerResult.message,
        admission.reason === 'THROTTLE_CAPACITY_EXCEEDED' ? 'SYSTEM_THROTTLED' : 'SYSTEM_LOCKDOWN',
        startTime,
        timestamp,
        options
      );
    }

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

      // Pre-normalization: produce ONE clean evaluation buffer up front.
      // Every regex/detection pass runs against this — never the raw text.
      const normalizedText = this.normalizeInput(ctx.text);

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

      // Step 2: Injection Detection — runs against the normalized buffer
      const injectionDetails = opts.injectionDetection
        ? this.detectInjections(normalizedText)
        : [];
      const criticalHitCount = injectionDetails.filter(d => d.severity === 'HIGH' || d.severity === 'CRITICAL').length;
      injectionsDetected += criticalHitCount;

      // Step 2b: Active Injection Redaction — CRITICAL/HIGH hits are
      // redacted (quarantined) from the output payload, never returned verbatim.
      let sanitizedText = normalizedText;
      const removedSegments: SanitizedSegment[] = [];
      let piiCount = 0;
      let secretCount = 0;

      if (opts.injectionDetection && criticalHitCount > 0) {
        const injectionResult = this.redactInjections(sanitizedText, injectionDetails);
        sanitizedText = injectionResult.text;
        // Dedupe segments across patterns before recording
        removedSegments.push(...this.sortAndMergeSegments(injectionResult.segments.map(seg => ({
          start: seg.start,
          end: seg.end,
          reason: 'INJECTION_PATTERN' as SanitizationReason,
          originalText: seg.originalText,
        }))));
      }

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

      // Step 5: Custom Rules — collect, merge overlaps, apply right-to-left.
      // Unordered/overlapping slice ranges would corrupt output indices, so we
      // sort descending by start and drop overlapping ranges first.
      if (this.customRules.length > 0) {
        const collected: SanitizedSegment[] = [];
        for (const rule of this.customRules) {
          let customSegments: SanitizedSegment[];
          try {
            customSegments = rule(sanitizedText, options.userContext) || [];
          } catch {
            customSegments = [];
          }
          collected.push(...customSegments.filter(s => s.end > s.start));
        }
        const merged = this.sortAndMergeSegments(collected);
        // Apply right-to-left (descending start) to preserve index integrity
        const descending = [...merged].sort((a, b) => b.start - a.start);
        for (const seg of descending) {
          sanitizedText = sanitizedText.slice(0, seg.start) + '[REDACTED]'.repeat(seg.end - seg.start) + sanitizedText.slice(seg.end);
          removedSegments.push(seg);
        }
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
        removedSegments: removedSegments.slice(0, TELEMETRY_MAX_ENTRIES),
        injectionDetected: injectionDetails.length > 0,
        injectionDetails: injectionDetails.slice(0, TELEMETRY_MAX_ENTRIES),
        securityFlags
      });
    }

    // Combine contexts if multiple
    const combinedText = allSanitizedContexts.map(c => c.text).join('\n\n---\n\n');
    // Telemetry bounding: cap retained arrays so memory scales with retained
    // telemetry (fixed cap), not with total input size.
    const combinedRemovedSegments = allSanitizedContexts.flatMap(c => c.removedSegments).slice(0, TELEMETRY_MAX_ENTRIES);
    const combinedInjectionDetails = allSanitizedContexts.flatMap(c => c.injectionDetails).slice(0, TELEMETRY_MAX_ENTRIES);
    const combinedSecurityFlags = allSanitizedContexts.flatMap(c => c.securityFlags).slice(0, TELEMETRY_MAX_ENTRIES);

    // Release the admission slot granted by the throughput governor at Step 0.
    this.ownerControl.release();

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
   * Fail-closed output for a tripped kill-switch or saturation throttle.
   * Drops 100% of context output — the returned text is a fixed operational
   * marker, never derived from request content.
   */
  private buildOwnerControlResult(
    message: string,
    flag: string,
    startTime: number,
    timestamp: string,
    options: SanitizeOptions
  ): SanitizeResult {
    const contexts = Array.isArray(options.rawContext) ? options.rawContext : [options.rawContext];
    const totalOriginalLength = contexts.reduce((sum, ctx) => sum + ctx.text.length, 0);
    return {
      success: true,
      sanitizedContext: {
        text: message,
        originalLength: totalOriginalLength,
        sanitizedLength: 0,
        removedSegments: [],
        injectionDetected: false,
        injectionDetails: [],
        securityFlags: [{ flag, severity: 'ERROR', message }]
      },
      telemetry: {
        timestamp,
        processingTimeMs: Date.now() - startTime,
        originalContextCount: contexts.length,
        totalOriginalLength,
        totalSanitizedLength: 0,
        injectionsDetected: 0,
        piiDetected: 0,
        secretsDetected: 0,
        permissionDenials: 0
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
    // Default-deny boundary: any runtime type error in metadata evaluation
    // yields accessDenied, never a thrown exception to the caller.
    const deny = (reason: string): PermissionEvaluation => ({
      allowed: false,
      reason,
      requiredPermissions: [],
      userPermissions: [],
      missingPermissions: [],
      accessLevelRequired: undefined,
      userAccessLevel: 0
    });

    try {
      const metadata = rawContext.metadata || {};

      // ------------------------------------------------------------------
      // Fix #3 — Defensive metadata schema boundaries (strict type guards).
      // ------------------------------------------------------------------
      const requiredDepartment = typeof metadata.requiredDepartment === 'string'
        ? metadata.requiredDepartment
        : undefined;

      // requiredPermissions: must be an array of strings. A declared non-array
      // payload fails closed (deny) rather than throwing on .filter().
      const hasDeclaredPermissions = metadata.requiredPermissions !== undefined && metadata.requiredPermissions !== null;
      let requiredPermissions: string[] = [];
      if (hasDeclaredPermissions) {
        if (!Array.isArray(metadata.requiredPermissions)) {
          return deny('Malformed requiredPermissions: expected an array, access denied');
        }
        requiredPermissions = (metadata.requiredPermissions as unknown[]).filter(p => typeof p === 'string') as string[];
      }

      // requiredRole: must be a string before .toLowerCase(). Invalid -> deny.
      const hasDeclaredRole = metadata.requiredRole !== undefined && metadata.requiredRole !== null;
      let requiredRole: string | undefined;
      if (hasDeclaredRole) {
        if (typeof metadata.requiredRole !== 'string') {
          return deny('Malformed requiredRole: expected a string, access denied');
        }
        requiredRole = metadata.requiredRole as string;
      }

      // Access level: strict numeric validation. A malformed declared level
      // fails closed rather than silently dropping the requirement.
      const hasDeclaredLevel = metadata.minAccessLevel !== undefined && metadata.minAccessLevel !== null;
      let requiredAccessLevel: number | undefined;
      if (hasDeclaredLevel) {
        if (typeof metadata.minAccessLevel !== 'number' || !Number.isFinite(metadata.minAccessLevel as number)) {
          return deny('Malformed minAccessLevel: expected a finite number, access denied');
        }
        requiredAccessLevel = metadata.minAccessLevel as number;
      }

      // contextTenantId: must be a non-empty string to be a valid tenant claim.
      const contextTenantId = typeof metadata.tenantId === 'string' && (metadata.tenantId as string).length > 0
        ? metadata.tenantId as string
        : undefined;
      const isGlobalPublic = metadata.isGlobalPublic === true;

      // ------------------------------------------------------------------
      // Fix #5 — Tenant isolation inversion (default-deny).
      // A chunk without an explicit tenantId is STRIPPED unless explicitly
      // tagged as a global public asset.
      // ------------------------------------------------------------------
      if (!isGlobalPublic) {
        if (contextTenantId === undefined) {
          return deny('Tenant isolation: chunk has no tenantId and is not a global public asset, access denied');
        }
        if (contextTenantId !== userContext.tenantId) {
          return {
            allowed: false,
            reason: `Tenant mismatch: context belongs to ${contextTenantId}, user is in ${userContext.tenantId}`,
            requiredPermissions,
            userPermissions: [],
            missingPermissions: [],
            accessLevelRequired: requiredAccessLevel,
            userAccessLevel: this.safeAccessLevel(userContext.accessLevel)
          };
        }
      }

      const safeUserRole = typeof userContext.role === 'string' ? userContext.role : '';
      const userPermissions = (Array.isArray(userContext.permissions) ? userContext.permissions : []).filter(p => typeof p === 'string');
      const userRoleLevel = safeUserRole ? (this.roleHierarchy[safeUserRole.toLowerCase()] || 1) : 1;
      const requiredRoleLevel = requiredRole ? (this.roleHierarchy[requiredRole.toLowerCase()] || 1) : 1;

      // Role check
      if (requiredRole && userRoleLevel < requiredRoleLevel) {
        return {
          allowed: false,
          reason: `Insufficient role: required ${requiredRole} (level ${requiredRoleLevel}), user has ${safeUserRole} (level ${userRoleLevel})`,
          requiredPermissions,
          userPermissions,
          missingPermissions: [],
          accessLevelRequired: requiredAccessLevel,
          userAccessLevel: this.safeAccessLevel(userContext.accessLevel)
        };
      }

      // Department check
      if (requiredDepartment && options?.allowedDepartments && !options.allowedDepartments.includes(requiredDepartment)) {
        return {
          allowed: false,
          reason: `Department access denied: required ${requiredDepartment}, allowed: ${options.allowedDepartments.join(', ')}`,
          requiredPermissions,
          userPermissions,
          missingPermissions: [],
          accessLevelRequired: requiredAccessLevel,
          userAccessLevel: this.safeAccessLevel(userContext.accessLevel)
        };
      }

      // ------------------------------------------------------------------
      // Fix #2 — Access-level type safety & default-deny gate.
      // userAccessLevel is 0 when missing/invalid; explicit numeric
      // satisfaction required: userAccessLevel >= requiredAccessLevel.
      // ------------------------------------------------------------------
      const userAccessLevel = this.safeAccessLevel(userContext.accessLevel);
      if (requiredAccessLevel !== undefined && userAccessLevel < requiredAccessLevel) {
        return {
          allowed: false,
          reason: `Insufficient access level: required ${requiredAccessLevel}, user has ${userAccessLevel}`,
          requiredPermissions,
          userPermissions,
          missingPermissions: [],
          accessLevelRequired: requiredAccessLevel,
          userAccessLevel
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
          userAccessLevel
        };
      }

      // Allowed roles check
      if (options?.allowedRoles && safeUserRole && !options.allowedRoles.includes(safeUserRole)) {
        return {
          allowed: false,
          reason: `Role not in allowed list: ${safeUserRole}`,
          requiredPermissions,
          userPermissions,
          missingPermissions: [],
          accessLevelRequired: requiredAccessLevel,
          userAccessLevel
        };
      }

      // Min access level check (option-level floor)
      if (options?.minAccessLevel !== undefined && Number.isFinite(options.minAccessLevel) && userAccessLevel < (options.minAccessLevel as number)) {
        return {
          allowed: false,
          reason: `Access level below minimum: ${userAccessLevel} < ${options.minAccessLevel}`,
          requiredPermissions,
          userPermissions,
          missingPermissions: [],
          accessLevelRequired: options.minAccessLevel as number,
          userAccessLevel
        };
      }

      return {
        allowed: true,
        reason: 'Access granted',
        requiredPermissions,
        userPermissions,
        missingPermissions: [],
        accessLevelRequired: requiredAccessLevel,
        userAccessLevel
      };
    } catch (err) {
      // Fail-closed: any unexpected runtime type error denies access.
      return deny(`Access evaluation failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Strict finite-number coercion for access levels. Returns 0 (most
   * restrictive) for undefined, NaN, boolean, string, or malformed values.
   */
  private safeAccessLevel(value: unknown): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : 0;
  }

  /**
   * Detect injection patterns in text.
   * Input is normalized ONCE into a clean evaluation buffer before any
   * regex runs, so obfuscated vectors (null-byte/control-char/zero-width/
   * NBSP/escaped) cannot bypass detection.
   */
  private detectInjections(text: string): InjectionDetail[] {
    const normalized = this.normalizeInput(text);
    const details: InjectionDetail[] = [];

    for (const pattern of this.injectionPatterns) {
      const regex = typeof pattern.pattern === 'string'
        ? new RegExp(pattern.pattern, 'gi')
        : new RegExp(pattern.pattern.source, pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g');

      let match;
      while ((match = regex.exec(normalized)) !== null) {
        // Guard against catastrophic zero-width matches to avoid infinite loops
        if (match[0].length === 0) {
          regex.lastIndex++;
          continue;
        }
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
   * Quarantine CRITICAL/HIGH severity injection matches from the output.
   * Ranges are merged (overlap-safe) and applied right-to-left so the
   * output buffer is never corrupted and vectors never survive verbatim.
   */
  private redactInjections(
    text: string,
    details: InjectionDetail[]
  ): { text: string; segments: Array<{ start: number; end: number; originalText: string }> } {
    const harmfulDetails = details.filter(d => d.severity === 'HIGH' || d.severity === 'CRITICAL');
    const replacement = '[INJECTION_REDACTED]';

    const ranges = harmfulDetails.map(d => ({
      start: d.position,
      end: d.position + d.match.length,
      originalText: d.match
    }));

    const merged = this.sortAndMergeSegments(ranges.map(r => ({
      start: r.start,
      end: r.end,
      reason: 'INJECTION_PATTERN' as SanitizationReason,
      originalText: r.originalText
    })));

    let result = text;
    // Right-to-left application preserves index integrity
    for (const seg of [...merged].sort((a, b) => b.start - a.start)) {
      result = result.slice(0, seg.start) + replacement + result.slice(seg.end);
    }

    return {
      text: result,
      segments: merged.map(s => ({
        start: s.start,
        end: s.start + replacement.length,
        originalText: s.originalText
      }))
    };
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
    // Under default-deny tenant isolation, the quick path threads the caller's
    // own tenantId so plain-text scans stay functional while remaining
    // tenant-scoped (never default-allow).
    const result = this.sanitize({
      userContext,
      rawContext: { text, metadata: { tenantId: userContext.tenantId ?? '' } },
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
  ownerControl?: SystemOwnerControl;
}): InfraLayerCore {
  return new InfraLayerCore(config);
}

/**
 * Default export for convenience
 */
export default InfraLayerCore;