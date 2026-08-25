"""
InfraLayer Python SDK - Type Definitions
=========================================

Mirrors the TypeScript SDK type definitions for consistency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class SanitizationReason(str, Enum):
    """Reasons for sanitization/redaction."""
    PII_DETECTED = "PII_DETECTED"
    SECRET_DETECTED = "SECRET_DETECTED"
    INJECTION_PATTERN = "INJECTION_PATTERN"
    ROLE_RESTRICTED = "ROLE_RESTRICTED"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    ACCESS_LEVEL_EXCEEDED = "ACCESS_LEVEL_EXCEEDED"
    CUSTOM_RULE = "CUSTOM_RULE"


class InjectionCategory(str, Enum):
    """Categories of injection attempts."""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    ROLE_MANIPULATION = "ROLE_MANIPULATION"
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    CHAIN_OF_THOUGHT_EXTRACTION = "CHAIN_OF_THOUGHT_EXTRACTION"
    CUSTOM = "CUSTOM"


class InjectionSeverity(str, Enum):
    """Severity levels for injection detection."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityFlagSeverity(str, Enum):
    """Severity levels for security flags."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class UserContext(BaseModel):
    """User context for sanitization and permission evaluation."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    user_id: str
    tenant_id: str
    role: str
    department: Optional[str] = None
    access_level: Optional[int] = None
    permissions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RawContext(BaseModel):
    """Raw context to be sanitized."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    text: str
    source: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SanitizedSegment(BaseModel):
    """A segment that was removed during sanitization."""
    model_config = ConfigDict(populate_by_name=True)

    start: int
    end: int
    reason: SanitizationReason
    original_text: str


class InjectionDetail(BaseModel):
    """Details about a detected injection attempt."""
    model_config = ConfigDict(populate_by_name=True)

    pattern: str
    match: str
    position: int
    severity: InjectionSeverity
    category: InjectionCategory


class InjectionPattern(BaseModel):
    """Custom injection pattern definition."""
    model_config = ConfigDict(populate_by_name=True)

    name: str
    pattern: str  # Regex pattern as string
    category: InjectionCategory
    severity: InjectionSeverity
    description: str


class SecurityFlag(BaseModel):
    """Security flag raised during sanitization."""
    model_config = ConfigDict(populate_by_name=True)

    flag: str
    severity: SecurityFlagSeverity
    message: str
    metadata: Optional[dict[str, Any]] = None


class PermissionEvaluation(BaseModel):
    """Result of permission evaluation."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    allowed: bool
    reason: str
    required_permissions: list[str]
    user_permissions: list[str]
    missing_permissions: Optional[list[str]] = None
    access_level_required: Optional[int] = None
    user_access_level: Optional[int] = None


class SanitizeOptions(BaseModel):
    """Options for sanitization."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    user_context: UserContext
    raw_context: Union[RawContext, list[RawContext]]
    options: Optional["SanitizeOptionsInner"] = None


class SanitizeOptionsInner(BaseModel):
    """Inner options for sanitization behavior."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    strict_mode: bool = False
    max_context_length: int = 100000
    custom_patterns: list[InjectionPattern] = Field(default_factory=list)
    allowed_roles: Optional[list[str]] = None
    allowed_departments: Optional[list[str]] = None
    min_access_level: Optional[int] = None
    pii_detection: bool = True
    secret_detection: bool = True
    injection_detection: bool = True
    role_evaluation: bool = True


class SanitizedContext(BaseModel):
    """Result of sanitization for a single context."""
    model_config = ConfigDict(populate_by_name=True)

    text: str
    original_length: int
    sanitized_length: int
    removed_segments: list[SanitizedSegment] = Field(default_factory=list)
    injection_detected: bool = False
    injection_details: list[InjectionDetail] = Field(default_factory=list)
    security_flags: list[SecurityFlag] = Field(default_factory=list)


class SanitizeTelemetry(BaseModel):
    """Telemetry data from sanitization."""
    model_config = ConfigDict(populate_by_name=True)

    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    processing_time_ms: int
    original_context_count: int
    total_original_length: int
    total_sanitized_length: int
    injections_detected: int
    pii_detected: int
    secrets_detected: int
    permission_denials: int


class SanitizeResult(BaseModel):
    """Complete result of sanitization."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    success: bool
    sanitized_context: Optional[SanitizedContext] = None
    permission_evaluation: Optional[PermissionEvaluation] = None
    error: Optional[str] = None
    telemetry: SanitizeTelemetry


class SanitizeRequestPayload(BaseModel):
    """Request payload for remote sanitize endpoint."""
    model_config = ConfigDict(populate_by_name=True)

    user_context: UserContext
    raw_context: Union[RawContext, list[RawContext]]
    options: Optional[SanitizeOptionsInner] = None


class SanitizeResponse(BaseModel):
    """Response from remote sanitize endpoint."""
    model_config = ConfigDict(populate_by_name=True)

    success: bool
    data: Optional[SanitizeResult] = None
    error: Optional[str] = None
    meta: Optional[dict[str, Any]] = None


class AuthRequestPayload(BaseModel):
    """Request payload for authentication."""
    model_config = ConfigDict(populate_by_name=True)

    api_key: str
    user_context: UserContext


class AuthResponse(BaseModel):
    """Response from authentication endpoint."""
    model_config = ConfigDict(populate_by_name=True)

    success: bool
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    model_config = ConfigDict(populate_by_name=True)

    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    timestamp: str
    checks: dict[str, str]


class InfraLayerConfig(BaseModel):
    """Configuration for InfraLayer client."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    api_url: str = "https://api.infralayer.io/v1"
    api_key: str = ""
    default_user_context: Optional[UserContext] = None
    timeout: float = 30.0
    max_retries: int = 3
    retry_base_delay: float = 1.0
    local_mode: bool = True
    core_instance: Any = None