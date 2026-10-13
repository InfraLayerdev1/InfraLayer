"""
InfraLayer Python SDK
=====================

Pre-LLM security filtering, sanitization, and telemetry client.
Supports both local (in-process) and remote (API) modes.

Quick Start:
    from infralayer import InfraLayer, create_local_infralayer, create_remote_infralayer

    # Local mode (zero-dependency, in-process)
    infra = create_local_infralayer()
    result = await infra.sanitize(
        "What is our PTO policy?",
        user_context={"user_id": "user-123", "tenant_id": "tenant-456", "role": "employee", "permissions": ["read:documents"]}
    )

    # Remote mode (API)
    infra = create_remote_infralayer(
        api_url="https://api.infralayer.io/v1",
        api_key="il_api_abc123...",
        default_user_context={"user_id": "service-user", "tenant_id": "tenant-456", "role": "system", "permissions": ["read:all"]}
    )
    result = await infra.sanitize("What is our PTO policy?")
"""

from .client import InfraLayer, create_infralayer
from .factory import create_local_infralayer, create_remote_infralayer
from .types import (
    UserContext,
    RawContext,
    SanitizedContext,
    SanitizeOptions,
    SanitizeOptionsInner,
    SanitizeResult,
    PermissionEvaluation,
    InjectionDetail,
    InjectionPattern,
    SecurityFlag,
    SanitizeTelemetry,
    SanitizationReason,
    InjectionCategory,
    InjectionSeverity,
    SecurityFlagSeverity,
    InfraLayerConfig,
    SanitizeRequestPayload,
    SanitizeResponse,
    AuthRequestPayload,
    AuthResponse,
    HealthResponse,
)
from .exceptions import (
    InfraLayerError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    SanitizationError,
    PermissionDeniedError,
    ConnectionError,
    TimeoutError,
    LocalModeError,
    RemoteModeError,
)

__version__ = "0.2.0"

__all__ = [
    # Main client
    "InfraLayer",
    # Factory functions
    "create_infralayer",
    "create_local_infralayer",
    "create_remote_infralayer",
    # Types
    "UserContext",
    "RawContext",
    "SanitizedContext",
    "SanitizeOptions",
    "SanitizeOptionsInner",
    "SanitizeResult",
    "PermissionEvaluation",
    "InjectionDetail",
    "InjectionPattern",
    "SecurityFlag",
    "SanitizeTelemetry",
    "SanitizationReason",
    "InjectionCategory",
    "InjectionSeverity",
    "SecurityFlagSeverity",
    "InfraLayerConfig",
    "SanitizeRequestPayload",
    "SanitizeResponse",
    "AuthRequestPayload",
    "AuthResponse",
    "HealthResponse",
    # Exceptions
    "InfraLayerError",
    "AuthenticationError",
    "RateLimitError",
    "ValidationError",
    "SanitizationError",
    "PermissionDeniedError",
    "ConnectionError",
    "TimeoutError",
    "LocalModeError",
    "RemoteModeError",
]