"""
InfraLayer Python SDK - Core Security Filter
=============================================

Zero-dependency pre-LLM context sanitization, injection detection,
and role-based permission evaluation. Runs 100% locally in-memory.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .types import (
    UserContext,
    RawContext,
    SanitizedContext,
    SanitizedSegment,
    SanitizationReason,
    InjectionDetail,
    InjectionPattern,
    InjectionCategory,
    InjectionSeverity,
    SecurityFlag,
    SecurityFlagSeverity,
    PermissionEvaluation,
    SanitizeOptions,
    SanitizeOptionsInner,
    SanitizeResult,
    SanitizeTelemetry,
)


# Default injection detection patterns for common LLM attack vectors
DEFAULT_INJECTION_PATTERNS: list[InjectionPattern] = [
    # Prompt Injection Patterns
    InjectionPattern(
        name="ignore_previous_instructions",
        pattern=r"(?:ignore|disregard|forget|override)\s+(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|directives?|commands?)",
        category=InjectionCategory.PROMPT_INJECTION,
        severity=InjectionSeverity.HIGH,
        description="Attempts to override system instructions",
    ),
    InjectionPattern(
        name="system_prompt_extraction",
        pattern=r"(?:show|reveal|display|print|output|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|directives?|guidelines?)",
        category=InjectionCategory.SYSTEM_PROMPT_LEAK,
        severity=InjectionSeverity.HIGH,
        description="Attempts to extract system prompt",
    ),
    InjectionPattern(
        name="role_manipulation",
        pattern=r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|simulate)\s+(?:an?\s+)?(?:admin|administrator|root|superuser|developer|system|unrestricted)",
        category=InjectionCategory.ROLE_MANIPULATION,
        severity=InjectionSeverity.HIGH,
        description="Attempts to manipulate AI role/permissions",
    ),
    InjectionPattern(
        name="jailbreak_dan",
        pattern=r"(?:DAN|Do\s+Anything\s+Now|Developer\s+Mode|Unrestricted\s+Mode|God\s+Mode|Free\s+Mode)",
        category=InjectionCategory.JAILBREAK_ATTEMPT,
        severity=InjectionSeverity.CRITICAL,
        description="Known jailbreak persona patterns",
    ),
    InjectionPattern(
        name="chain_of_thought_extraction",
        pattern=r"(?:show|reveal|display|output|print)\s+(?:your|the)\s+(?:reasoning|thinking|chain\s+of\s+thought|internal\s+monologue|step\s+by\s+step)",
        category=InjectionCategory.CHAIN_OF_THOUGHT_EXTRACTION,
        severity=InjectionSeverity.MEDIUM,
        description="Attempts to extract reasoning process",
    ),
    InjectionPattern(
        name="data_exfiltration",
        pattern=r"(?:output|print|display|show|return|send|transmit|leak)\s+(?:all|every|the)\s+(?:data|information|records?|documents?|users?|passwords?|keys?|tokens?|secrets?)",
        category=InjectionCategory.DATA_EXFILTRATION,
        severity=InjectionSeverity.CRITICAL,
        description="Attempts to extract sensitive data",
    ),
    InjectionPattern(
        name="instruction_overwrite",
        pattern=r"(?:new\s+instructions?|updated\s+instructions?|replace\s+instructions?|system\s+update|override\s+system)",
        category=InjectionCategory.PROMPT_INJECTION,
        severity=InjectionSeverity.HIGH,
        description="Attempts to overwrite system instructions",
    ),
    InjectionPattern(
        name="delimiter_injection",
        pattern=r"(?:---|===|```|<<<|>>>|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>)",
        category=InjectionCategory.PROMPT_INJECTION,
        severity=InjectionSeverity.MEDIUM,
        description="Special delimiter tokens that could confuse the model",
    ),
    InjectionPattern(
        name="encoding_obfuscation",
        pattern=r"(?:base64|rot13|hex|unicode|url\s*encode|html\s*entity)",
        category=InjectionCategory.PROMPT_INJECTION,
        severity=InjectionSeverity.MEDIUM,
        description="Encoding/obfuscation attempts to bypass filters",
    ),
]

# PII Detection Patterns
PII_PATTERNS: list[tuple[str, str, str]] = [
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL_REDACTED]"),
    ("phone_us", r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b", "[PHONE_REDACTED]"),
    ("ssn", r"\b\d{3}-?\d{2}-?\d{4}\b", "[SSN_REDACTED]"),
    ("credit_card", r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[CARD_REDACTED]"),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP_REDACTED]"),
    ("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "[IP_REDACTED]"),
    ("uuid", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "[UUID_REDACTED]"),
]

# Secret Detection Patterns
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("api_key_generic", r"\b(?:api[_-]?key|apikey)\s*[:=]?\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?", "[API_KEY_REDACTED]"),
    ("openai_api_key", r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", "[API_KEY_REDACTED]"),
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "[AWS_KEY_REDACTED]"),
    ("aws_secret_key", r"\b[0-9a-zA-Z/+]{40}\b", "[AWS_SECRET_REDACTED]"),
    ("github_token", r"\bgh[ps]_[A-Za-z0-9]{36,}\b", "[GITHUB_TOKEN_REDACTED]"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "[SLACK_TOKEN_REDACTED]"),
    ("jwt_token", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[JWT_REDACTED]"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[PRIVATE_KEY_REDACTED]"),
    ("connection_string", r"(?:mongodb|postgres|mysql|redis):\/\/[^\s]+", "[CONNECTION_STRING_REDACTED]"),
    ("password_assignment", r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", "[PASSWORD_REDACTED]"),
]

# Default role hierarchy (higher number = more access)
DEFAULT_ROLE_HIERARCHY: dict[str, int] = {
    "viewer": 1,
    "employee": 2,
    "member": 2,
    "analyst": 3,
    "manager": 4,
    "lead": 4,
    "director": 5,
    "admin": 6,
    "administrator": 6,
    "superadmin": 7,
    "owner": 7,
}


@dataclass
class InfraLayerCore:
    """
    InfraLayer Security Filter Core Class.
    Provides zero-dependency, in-memory pre-LLM security filtering.
    """

    injection_patterns: list[InjectionPattern] = field(default_factory=list)
    pii_patterns: list[tuple[str, str, str]] = field(default_factory=list)
    secret_patterns: list[tuple[str, str, str]] = field(default_factory=list)
    role_hierarchy: dict[str, int] = field(default_factory=dict)
    custom_rules: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.injection_patterns:
            self.injection_patterns = DEFAULT_INJECTION_PATTERNS.copy()
        if not self.pii_patterns:
            self.pii_patterns = PII_PATTERNS.copy()
        if not self.secret_patterns:
            self.secret_patterns = SECRET_PATTERNS.copy()
        if not self.role_hierarchy:
            self.role_hierarchy = DEFAULT_ROLE_HIERARCHY.copy()
        if not self.custom_rules:
            self.custom_rules = []

    def sanitize(self, options: SanitizeOptions) -> SanitizeResult:
        """
        Main sanitization entry point.
        """
        start_time = time.perf_counter()
        timestamp = datetime.utcnow().isoformat() + "Z"

        contexts = options.raw_context if isinstance(options.raw_context, list) else [options.raw_context]
        opts = options.options or SanitizeOptionsInner()

        total_original_length = 0
        total_sanitized_length = 0
        injections_detected = 0
        pii_detected = 0
        secrets_detected = 0
        permission_denials = 0

        all_sanitized_contexts: list[SanitizedContext] = []

        for ctx in contexts:
            total_original_length += len(ctx.text)

            # Step 1: Permission Evaluation
            permission_eval = (
                self._evaluate_permissions(options.user_context, ctx, opts)
                if opts.role_evaluation
                else PermissionEvaluation(
                    allowed=True,
                    reason="Role evaluation disabled",
                    required_permissions=[],
                    user_permissions=[],
                )
            )

            if not permission_eval.allowed:
                permission_denials += 1
                all_sanitized_contexts.append(
                    SanitizedContext(
                        text="[CONTEXT BLOCKED: Insufficient permissions]",
                        original_length=len(ctx.text),
                        sanitized_length=0,
                        removed_segments=[
                            SanitizedSegment(
                                start=0,
                                end=len(ctx.text),
                                reason=SanitizationReason.ROLE_RESTRICTED,
                                original_text=ctx.text,
                            )
                        ],
                        injection_detected=False,
                        injection_details=[],
                        security_flags=[
                            SecurityFlag(
                                flag="PERMISSION_DENIED",
                                severity=SecurityFlagSeverity.ERROR,
                                message=permission_eval.reason,
                                metadata=permission_eval.model_dump(),
                            )
                        ],
                    )
                )
                continue

            # Step 2: Injection Detection
            injection_details = self._detect_injections(ctx.text) if opts.injection_detection else []
            injections_detected += sum(
                1 for d in injection_details if d.severity in (InjectionSeverity.HIGH, InjectionSeverity.CRITICAL)
            )

            # Step 3: PII Detection & Redaction
            sanitized_text = ctx.text
            removed_segments: list[SanitizedSegment] = []
            pii_count = 0
            secret_count = 0

            if opts.pii_detection:
                sanitized_text, pii_segments = self._redact_patterns(sanitized_text, self.pii_patterns, SanitizationReason.PII_DETECTED)
                removed_segments.extend(pii_segments)
                pii_count = len(pii_segments)
                pii_detected += pii_count

            # Step 4: Secret Detection & Redaction
            if opts.secret_detection:
                sanitized_text, secret_segments = self._redact_patterns(sanitized_text, self.secret_patterns, SanitizationReason.SECRET_DETECTED)
                removed_segments.extend(secret_segments)
                secret_count = len(secret_segments)
                secrets_detected += secret_count

            # Step 5: Custom Rules
            for rule in self.custom_rules:
                custom_segments = rule(sanitized_text, options.user_context)
                for seg in custom_segments:
                    # Replace with redacted text of same length
                    replacement = "[REDACTED]" * (seg.end - seg.start)
                    sanitized_text = sanitized_text[: seg.start] + replacement + sanitized_text[seg.end :]
                removed_segments.extend(custom_segments)

            # Step 6: Length Limiting
            if len(sanitized_text) > opts.max_context_length:
                excess = len(sanitized_text) - opts.max_context_length
                sanitized_text = sanitized_text[: opts.max_context_length] + "... [TRUNCATED]"
                removed_segments.append(
                    SanitizedSegment(
                        start=opts.max_context_length,
                        end=opts.max_context_length + excess,
                        reason=SanitizationReason.CUSTOM_RULE,
                        original_text=ctx.text[opts.max_context_length : opts.max_context_length + excess],
                    )
                )

            total_sanitized_length += len(sanitized_text)

            # Step 7: Security Flags
            security_flags: list[SecurityFlag] = []
            if injection_details:
                security_flags.append(
                    SecurityFlag(
                        flag="INJECTION_DETECTED",
                        severity=(
                            SecurityFlagSeverity.ERROR
                            if any(d.severity == InjectionSeverity.CRITICAL for d in injection_details)
                            else SecurityFlagSeverity.WARNING
                        ),
                        message=f"Detected {len(injection_details)} injection attempt(s)",
                        metadata={"details": [d.model_dump() for d in injection_details]},
                    )
                )
            if pii_count > 0:
                security_flags.append(
                    SecurityFlag(
                        flag="PII_REDACTED",
                        severity=SecurityFlagSeverity.WARNING,
                        message=f"Redacted {pii_count} PII instance(s)",
                        metadata={"count": pii_count},
                    )
                )
            if secret_count > 0:
                security_flags.append(
                    SecurityFlag(
                        flag="SECRET_REDACTED",
                        severity=SecurityFlagSeverity.ERROR,
                        message=f"Redacted {secret_count} secret(s)",
                        metadata={"count": secret_count},
                    )
                )

            all_sanitized_contexts.append(
                SanitizedContext(
                    text=sanitized_text,
                    original_length=len(ctx.text),
                    sanitized_length=len(sanitized_text),
                    removed_segments=removed_segments,
                    injection_detected=len(injection_details) > 0,
                    injection_details=injection_details,
                    security_flags=security_flags,
                )
            )

        # Combine contexts if multiple
        combined_text = "\n\n---\n\n".join(c.text for c in all_sanitized_contexts)
        combined_removed_segments = [seg for c in all_sanitized_contexts for seg in c.removed_segments]
        combined_injection_details = [d for c in all_sanitized_contexts for d in c.injection_details]
        combined_security_flags = [f for c in all_sanitized_contexts for f in c.security_flags]

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)

        return SanitizeResult(
            success=True,
            sanitized_context=SanitizedContext(
                text=combined_text,
                original_length=total_original_length,
                sanitized_length=total_sanitized_length,
                removed_segments=combined_removed_segments,
                injection_detected=len(combined_injection_details) > 0,
                injection_details=combined_injection_details,
                security_flags=combined_security_flags,
            ),
            permission_evaluation=(
                self._evaluate_permissions(options.user_context, contexts[0], opts)
                if len(contexts) == 1
                else None
            ),
            telemetry=SanitizeTelemetry(
                timestamp=timestamp,
                processing_time_ms=processing_time_ms,
                original_context_count=len(contexts),
                total_original_length=total_original_length,
                total_sanitized_length=total_sanitized_length,
                injections_detected=injections_detected,
                pii_detected=pii_detected,
                secrets_detected=secrets_detected,
                permission_denials=permission_denials,
            ),
        )

    def _evaluate_permissions(
        self,
        user_context: UserContext,
        raw_context: RawContext,
        options: SanitizeOptionsInner,
    ) -> PermissionEvaluation:
        """Evaluate if user has permission to access the context."""
        required_permissions = raw_context.metadata.get("requiredPermissions", [])
        required_role = raw_context.metadata.get("requiredRole")
        required_department = raw_context.metadata.get("requiredDepartment")
        required_access_level = raw_context.metadata.get("minAccessLevel")
        context_tenant_id = raw_context.metadata.get("tenantId")

        user_permissions = user_context.permissions or []
        user_role_level = self.role_hierarchy.get(user_context.role.lower(), 1)
        required_role_level = self.role_hierarchy.get(required_role.lower(), 1) if required_role else 1

        # Tenant isolation check
        if context_tenant_id and context_tenant_id != user_context.tenant_id:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Tenant mismatch: context belongs to {context_tenant_id}, user is in {user_context.tenant_id}",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                access_level_required=required_access_level,
                user_access_level=user_context.access_level,
            )

        # Role check
        if required_role and user_role_level < required_role_level:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Insufficient role: required {required_role} (level {required_role_level}), user has {user_context.role} (level {user_role_level})",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                access_level_required=required_access_level,
                user_access_level=user_context.access_level,
            )

        # Department check
        if required_department and options.allowed_departments and required_department not in options.allowed_departments:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Department access denied: required {required_department}, allowed: {', '.join(options.allowed_departments)}",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                access_level_required=required_access_level,
                user_access_level=user_context.access_level,
            )

        # Access level check
        if required_access_level and user_context.access_level and user_context.access_level < required_access_level:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Insufficient access level: required {required_access_level}, user has {user_context.access_level}",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                access_level_required=required_access_level,
                user_access_level=user_context.access_level,
            )

        # Permission check
        missing_permissions = [p for p in required_permissions if p not in user_permissions]
        if missing_permissions:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Missing permissions: {', '.join(missing_permissions)}",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                missing_permissions=missing_permissions,
                access_level_required=required_access_level,
                user_access_level=user_context.access_level,
            )

        # Allowed roles check
        if options.allowed_roles and user_context.role not in options.allowed_roles:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Role not in allowed list: {user_context.role}",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                access_level_required=required_access_level,
                user_access_level=user_context.access_level,
            )

        # Min access level check
        if options.min_access_level and user_context.access_level and user_context.access_level < options.min_access_level:
            return PermissionEvaluation(
                allowed=False,
                reason=f"Access level below minimum: {user_context.access_level} < {options.min_access_level}",
                required_permissions=required_permissions,
                user_permissions=user_permissions,
                access_level_required=options.min_access_level,
                user_access_level=user_context.access_level,
            )

        return PermissionEvaluation(
            allowed=True,
            reason="Access granted",
            required_permissions=required_permissions,
            user_permissions=user_permissions,
            missing_permissions=[],
            access_level_required=required_access_level,
            user_access_level=user_context.access_level,
        )

    def _detect_injections(self, text: str) -> list[InjectionDetail]:
        """Detect injection patterns in text."""
        details: list[InjectionDetail] = []

        for pattern in self.injection_patterns:
            try:
                regex = re.compile(pattern.pattern, re.IGNORECASE)
            except re.error:
                continue

            for match in regex.finditer(text):
                details.append(
                    InjectionDetail(
                        pattern=pattern.name,
                        match=match.group(0),
                        position=match.start(),
                        severity=pattern.severity,
                        category=pattern.category,
                    )
                )

        return details

    def _redact_patterns(
        self,
        text: str,
        patterns: list[tuple[str, str, str]],
        reason: SanitizationReason,
    ) -> tuple[str, list[SanitizedSegment]]:
        """Redact patterns from text."""
        result = text
        segments: list[SanitizedSegment] = []

        for name, pattern_str, replacement in patterns:
            try:
                regex = re.compile(pattern_str)
            except re.error:
                continue

            matches: list[tuple[int, int, str]] = []
            for match in regex.finditer(text):
                matches.append((match.start(), match.end(), match.group(0)))

            # Apply replacements from end to start to maintain indices
            for start, end, match_text in reversed(matches):
                result = result[:start] + replacement + result[end:]
                segments.append(
                    SanitizedSegment(
                        start=start,
                        end=start + len(replacement),
                        reason=reason,
                        original_text=match_text,
                    )
                )

        return result, segments

    def quick_sanitize(self, text: str, user_context: UserContext) -> str:
        """Quick sanitize for simple use cases."""
        result = self.sanitize(
            SanitizeOptions(
                user_context=user_context,
                raw_context=RawContext(text=text),
                options=SanitizeOptionsInner(strict_mode=True),
            )
        )
        return result.sanitized_context.text if result.sanitized_context else "[BLOCKED]"

    def scan_for_injections(self, text: str) -> list[InjectionDetail]:
        """Scan for injections without sanitizing."""
        return self._detect_injections(text)

    def check_permission(
        self,
        user_context: UserContext,
        required_permissions: list[str],
        required_role: Optional[str] = None,
        required_access_level: Optional[int] = None,
        required_department: Optional[str] = None,
    ) -> PermissionEvaluation:
        """Check if user has permission for a specific action."""
        mock_context = RawContext(
            text="",
            metadata={
                "requiredPermissions": required_permissions,
                "requiredRole": required_role,
                "requiredDepartment": required_department,
                "minAccessLevel": required_access_level,
                "tenantId": user_context.tenant_id,
            },
        )
        return self._evaluate_permissions(
            user_context,
            mock_context,
            SanitizeOptionsInner(
                allowed_roles=list(self.role_hierarchy.keys()),
                allowed_departments=[user_context.department] if user_context.department else [],
                min_access_level=required_access_level,
            ),
        )


def create_infralayer_core(
    custom_injection_patterns: Optional[list[InjectionPattern]] = None,
    custom_pii_patterns: Optional[list[tuple[str, str, str]]] = None,
    custom_secret_patterns: Optional[list[tuple[str, str, str]]] = None,
    role_hierarchy: Optional[dict[str, int]] = None,
    custom_rules: Optional[list] = None,
) -> InfraLayerCore:
    """Factory function for creating a pre-configured InfraLayerCore instance."""
    return InfraLayerCore(
        injection_patterns=(DEFAULT_INJECTION_PATTERNS + (custom_injection_patterns or [])),
        pii_patterns=(PII_PATTERNS + (custom_pii_patterns or [])),
        secret_patterns=(SECRET_PATTERNS + (custom_secret_patterns or [])),
        role_hierarchy={**DEFAULT_ROLE_HIERARCHY, **(role_hierarchy or {})},
        custom_rules=custom_rules or [],
    )