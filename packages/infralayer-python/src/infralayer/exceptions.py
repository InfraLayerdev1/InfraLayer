"""
InfraLayer Python SDK - Custom Exception Types
===============================================

Custom exceptions for different error scenarios in the InfraLayer SDK.
"""

from __future__ import annotations

from typing import Any, Optional


class InfraLayerError(Exception):
    """Base exception for all InfraLayer errors."""

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, code={self.code!r}, status_code={self.status_code!r})"

    def __str__(self) -> str:
        parts = [self.message]
        if self.code:
            parts.append(f"[code: {self.code}]")
        if self.status_code:
            parts.append(f"[status: {self.status_code}]")
        return " ".join(parts)


class AuthenticationError(InfraLayerError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        *,
        code: str = "AUTH_FAILED",
        details: Optional[dict[str, Any]] = None,
        status_code: int = 401,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class RateLimitError(InfraLayerError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        code: str = "RATE_LIMIT_EXCEEDED",
        details: Optional[dict[str, Any]] = None,
        status_code: int = 429,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)
        self.retry_after = retry_after


class ValidationError(InfraLayerError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        *,
        code: str = "VALIDATION_ERROR",
        details: Optional[dict[str, Any]] = None,
        status_code: int = 400,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class SanitizationError(InfraLayerError):
    """Raised when sanitization fails."""

    def __init__(
        self,
        message: str = "Sanitization failed",
        *,
        code: str = "SANITIZATION_ERROR",
        details: Optional[dict[str, Any]] = None,
        status_code: int = 500,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class PermissionDeniedError(InfraLayerError):
    """Raised when permission check fails."""

    def __init__(
        self,
        message: str = "Permission denied",
        *,
        code: str = "PERMISSION_DENIED",
        details: Optional[dict[str, Any]] = None,
        status_code: int = 403,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class ConnectionError(InfraLayerError):
    """Raised when connection to remote API fails."""

    def __init__(
        self,
        message: str = "Connection failed",
        *,
        code: str = "CONNECTION_ERROR",
        details: Optional[dict[str, Any]] = None,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class TimeoutError(InfraLayerError):
    """Raised when request times out."""

    def __init__(
        self,
        message: str = "Request timed out",
        *,
        code: str = "TIMEOUT",
        details: Optional[dict[str, Any]] = None,
        status_code: int = 408,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class ConfigurationError(InfraLayerError):
    """Raised when configuration is invalid."""

    def __init__(
        self,
        message: str = "Invalid configuration",
        *,
        code: str = "CONFIGURATION_ERROR",
        details: Optional[dict[str, Any]] = None,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=status_code)


class LocalModeError(InfraLayerError):
    """Raised when a remote-only operation is called in local mode."""

    def __init__(
        self,
        message: str = "Operation not available in local mode",
        *,
        code: str = "LOCAL_MODE_ERROR",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=400)


class RemoteModeError(InfraLayerError):
    """Raised when a local-only operation is called in remote mode."""

    def __init__(
        self,
        message: str = "Operation not available in remote mode",
        *,
        code: str = "REMOTE_MODE_ERROR",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details, status_code=400)