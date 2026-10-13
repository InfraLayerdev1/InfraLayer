"""
InfraLayer Python SDK - Main Client
====================================

Provides both local (in-process) and remote (API) sanitization capabilities
with async/sync support, auto-retry logic, JWT header propagation, and more.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any, Callable, Optional, Union

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep,
)
import logging

from .core import InfraLayerCore, create_infralayer_core
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
    ConfigurationError,
)
from .types import (
    UserContext,
    RawContext,
    SanitizedContext,
    SanitizeOptions,
    SanitizeOptionsInner,
    SanitizeResult,
    PermissionEvaluation,
    InjectionDetail,
    SanitizeTelemetry,
    SanitizeRequestPayload,
    SanitizeResponse,
    AuthRequestPayload,
    AuthResponse,
    HealthResponse,
    InfraLayerConfig,
)


logger = logging.getLogger(__name__)


def _default_on_request(config: httpx.Request) -> None:
    """Default request hook."""
    logger.debug(f"Request: {config.method} {config.url}")


def _default_on_response(response: httpx.Response) -> None:
    """Default response hook."""
    logger.debug(f"Response: {response.status_code}")


def _default_on_error(error: Exception) -> None:
    """Default error hook."""
    logger.error(f"Request error: {error}")


class InfraLayer:
    """
    InfraLayer SDK Client Class.
    Provides both local (in-process) and remote (API) sanitization capabilities.
    """

    def __init__(self, config: Optional[InfraLayerConfig] = None) -> None:
        self.config = config or InfraLayerConfig()
        self._auth_token: Optional[str] = None
        self._token_expiry: float = 0
        self._core: Optional[InfraLayerCore] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None
        self._local_mode = self.config.local_mode

        # Initialize local core if in local mode
        if self._local_mode:
            self._core = self.config.core_instance or create_infralayer_core()

    @property
    def local_mode(self) -> bool:
        """Whether the client is in local mode."""
        return self._local_mode

    @local_mode.setter
    def local_mode(self, value: bool) -> None:
        self._local_mode = value
        if value and self._core is None:
            self._core = self.config.core_instance or create_infralayer_core()

    def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.api_url,
                timeout=httpx.Timeout(self.config.timeout),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"infralayer-python/{__import__('infralayer').__version__}",
                },
            )
            # Add event hooks
            self._client.event_hooks["request"].append(_default_on_request)
            self._client.event_hooks["response"].append(_default_on_response)
        return self._client

    def _get_sync_client(self) -> httpx.Client:
        """Get or create sync HTTP client."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                base_url=self.config.api_url,
                timeout=httpx.Timeout(self.config.timeout),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"infralayer-python/{__import__('infralayer').__version__}",
                },
            )
            # Add event hooks
            self._sync_client.event_hooks["request"].append(_default_on_request)
            self._sync_client.event_hooks["response"].append(_default_on_response)
        return self._sync_client

    async def _ensure_auth_token(self) -> Optional[str]:
        """Ensure we have a valid auth token, refreshing if needed."""
        if self._local_mode:
            return None

        if self._auth_token and time.time() < self._token_expiry:
            return self._auth_token

        if not self.config.api_key:
            return None

        await self._refresh_auth_token()
        return self._auth_token

    def _ensure_auth_token_sync(self) -> Optional[str]:
        """Sync version of ensure auth token."""
        if self._local_mode:
            return None

        if self._auth_token and time.time() < self._token_expiry:
            return self._auth_token

        if not self.config.api_key:
            return None

        self._refresh_auth_token_sync()
        return self._auth_token

    async def _refresh_auth_token(self) -> None:
        """Refresh authentication token using API key."""
        if self._local_mode:
            raise LocalModeError("Cannot refresh token in local mode")

        client = self._get_async_client()
        payload = AuthRequestPayload(
            api_key=self.config.api_key,
            user_context=self.config.default_user_context or UserContext(user_id="", tenant_id="", role=""),
        )

        try:
            response = await self._execute_with_retry_async(
                lambda: client.post("/auth", json=payload.model_dump())
            )
            data = AuthResponse(**await response.json())

            if not data.success:
                raise AuthenticationError(data.error or "Authentication failed")

            self._auth_token = data.data["token"]
            self._token_expiry = time.time() + data.data["expiresIn"]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("Invalid API key")
            raise ConnectionError(f"Auth request failed: {e}")
        except Exception as e:
            raise ConnectionError(f"Failed to refresh auth token: {e}")

    def _refresh_auth_token_sync(self) -> None:
        """Sync version of refresh auth token."""
        if self._local_mode:
            raise LocalModeError("Cannot refresh token in local mode")

        client = self._get_sync_client()
        payload = AuthRequestPayload(
            api_key=self.config.api_key,
            user_context=self.config.default_user_context or UserContext(user_id="", tenant_id="", role=""),
        )

        try:
            response = self._execute_with_retry_sync(
                lambda: client.post("/auth", json=payload.model_dump())
            )
            data = AuthResponse(**response.json())

            if not data.success:
                raise AuthenticationError(data.error or "Authentication failed")

            self._auth_token = data.data["token"]
            self._token_expiry = time.time() + data.data["expiresIn"]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("Invalid API key")
            raise ConnectionError(f"Auth request failed: {e}")
        except Exception as e:
            raise ConnectionError(f"Failed to refresh auth token: {e}")

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers for requests."""
        headers = {}
        if self._local_mode:
            return headers

        if self._auth_token and time.time() < self._token_expiry:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        elif self.config.api_key:
            headers["x-api-key"] = self.config.api_key

        return headers

    def _is_retryable_error(self, error: Exception) -> bool:
        """Check if error is retryable."""
        if isinstance(error, (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError)):
            return True
        if isinstance(error, httpx.HTTPStatusError):
            status = error.response.status_code
            return status == 429 or status >= 500
        if isinstance(error, (ConnectionError, TimeoutError)):
            return True
        if isinstance(error, RateLimitError):
            return True
        return False

    async def _execute_with_retry_async(
        self,
        operation: Callable[[], Any],
        retries: Optional[int] = None,
    ) -> Any:
        """Execute async operation with retry logic and exponential backoff."""
        max_retries = retries if retries is not None else self.config.max_retries
        base_delay = self.config.retry_base_delay

        @retry(
            retry=retry_if_exception_type(Exception),
            stop=stop_after_attempt(max_retries + 1),
            wait=wait_exponential(multiplier=base_delay, min=base_delay, max=30),
            before_sleep=lambda retry_state: logger.warning(f"Retrying after error: {retry_state.outcome.exception()}"),
            reraise=True,
        )
        async def _execute() -> Any:
            try:
                return await operation()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401 and self.config.api_key and not self._local_mode:
                    # Try to refresh token and retry once
                    await self._refresh_auth_token()
                    # Retry with new token
                    return await operation()
                if self._is_retryable_error(e):
                    raise
                raise
            except Exception as e:
                if self._is_retryable_error(e):
                    raise
                raise

        return await _execute()

    def _execute_with_retry_sync(
        self,
        operation: Callable[[], Any],
        retries: Optional[int] = None,
    ) -> Any:
        """Execute sync operation with retry logic and exponential backoff."""
        max_retries = retries if retries is not None else self.config.max_retries
        base_delay = self.config.retry_base_delay

        @retry(
            retry=retry_if_exception_type(Exception),
            stop=stop_after_attempt(max_retries + 1),
            wait=wait_exponential(multiplier=base_delay, min=base_delay, max=30),
            before_sleep=lambda retry_state: logger.warning(f"Retrying after error: {retry_state.outcome.exception()}"),
            reraise=True,
        )
        def _execute() -> Any:
            try:
                return operation()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401 and self.config.api_key and not self._local_mode:
                    self._refresh_auth_token_sync()
                    return operation()
                if self._is_retryable_error(e):
                    raise
                raise
            except Exception as e:
                if self._is_retryable_error(e):
                    raise
                raise

        return _execute()

    # =========================================================================
    # Public API - Async Methods
    # =========================================================================

    async def sanitize(
        self,
        raw_context: Union[RawContext, list[RawContext], str],
        user_context: Optional[UserContext] = None,
        options: Optional[SanitizeOptionsInner] = None,
    ) -> SanitizeResult:
        """
        Main sanitize method - works in both local and remote modes.

        Args:
            raw_context: Text or RawContext object(s) to sanitize
            user_context: User context for permission evaluation (uses default if not provided)
            options: Sanitization options

        Returns:
            SanitizeResult with sanitized context and telemetry
        """
        effective_user_context = user_context or self.config.default_user_context
        if not effective_user_context:
            raise ValidationError("User context is required. Provide it in the call or set default_user_context in config.")

        # Handle string input
        if isinstance(raw_context, str):
            raw_context = RawContext(text=raw_context)

        if self._local_mode:
            return self._sanitize_local(raw_context, effective_user_context, options)
        else:
            return await self._sanitize_remote(raw_context, effective_user_context, options)

    def _sanitize_local(
        self,
        raw_context: Union[RawContext, list[RawContext]],
        user_context: UserContext,
        options: Optional[SanitizeOptionsInner],
    ) -> SanitizeResult:
        """Local in-process sanitization."""
        if self._core is None:
            raise ConfigurationError("Local core not initialized")

        sanitize_options = SanitizeOptions(
            user_context=user_context,
            raw_context=raw_context,
            options=options,
        )
        return self._core.sanitize(sanitize_options)

    async def _sanitize_remote(
        self,
        raw_context: Union[RawContext, list[RawContext]],
        user_context: UserContext,
        options: Optional[SanitizeOptionsInner],
    ) -> SanitizeResult:
        """Remote API sanitization."""
        await self._ensure_auth_token()

        payload = SanitizeRequestPayload(
            user_context=user_context,
            raw_context=raw_context,
            options=options,
        )

        client = self._get_async_client()
        headers = self._get_auth_headers()

        try:
            response = await self._execute_with_retry_async(
                lambda: client.post("/sanitize", json=payload.model_dump(), headers=headers)
            )
            response.raise_for_status()
            data = SanitizeResponse(**await response.json())

            if not data.success:
                raise SanitizationError(data.error or "Sanitization failed")

            return data.data
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                retry_after = float(e.response.headers.get("Retry-After", "1"))
                raise RateLimitError("Rate limit exceeded", retry_after=retry_after)
            if e.response.status_code == 403:
                raise PermissionDeniedError("Permission denied for sanitization")
            if e.response.status_code == 400:
                raise ValidationError(e.response.text)
            raise SanitizationError(f"API error: {e.response.status_code} - {e.response.text}")

    def sanitize_sync(
        self,
        raw_context: Union[RawContext, list[RawContext], str],
        user_context: Optional[UserContext] = None,
        options: Optional[SanitizeOptionsInner] = None,
    ) -> SanitizeResult:
        """
        Synchronous version of sanitize() for non-async contexts.

        Args:
            raw_context: Text or RawContext object(s) to sanitize
            user_context: User context for permission evaluation (uses default if not provided)
            options: Sanitization options

        Returns:
            SanitizeResult with sanitized context and telemetry
        """
        effective_user_context = user_context or self.config.default_user_context
        if not effective_user_context:
            raise ValidationError("User context is required. Provide it in the call or set default_user_context in config.")

        # Handle string input
        if isinstance(raw_context, str):
            raw_context = RawContext(text=raw_context)

        if self._local_mode:
            return self._sanitize_local(raw_context, effective_user_context, options)
        else:
            return self._sanitize_remote_sync(raw_context, effective_user_context, options)

    def _sanitize_remote_sync(
        self,
        raw_context: Union[RawContext, list[RawContext]],
        user_context: UserContext,
        options: Optional[SanitizeOptionsInner],
    ) -> SanitizeResult:
        """Sync remote API sanitization."""
        self._ensure_auth_token_sync()

        payload = SanitizeRequestPayload(
            user_context=user_context,
            raw_context=raw_context,
            options=options,
        )

        client = self._get_sync_client()
        headers = self._get_auth_headers()

        try:
            response = self._execute_with_retry_sync(
                lambda: client.post("/sanitize", json=payload.model_dump(), headers=headers)
            )
            data = SanitizeResponse(**response.json())

            if not data.success:
                raise SanitizationError(data.error or "Sanitization failed")

            return data.data
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                retry_after = float(e.response.headers.get("Retry-After", "1"))
                raise RateLimitError("Rate limit exceeded", retry_after=retry_after)
            if e.response.status_code == 403:
                raise PermissionDeniedError("Permission denied for sanitization")
            if e.response.status_code == 400:
                raise ValidationError(e.response.text)
            raise SanitizationError(f"API error: {e.response.status_code} - {e.response.text}")

    async def quick_sanitize(self, text: str, user_context: Optional[UserContext] = None) -> str:
        """
        Quick sanitize for simple use cases (local mode only).

        Args:
            text: Text to sanitize
            user_context: User context

        Returns:
            Sanitized text string
        """
        effective_user_context = user_context or self.config.default_user_context
        if not effective_user_context:
            raise ValidationError("User context is required")

        if self._local_mode:
            if self._core is None:
                raise ConfigurationError("Local core not initialized")
            return self._core.quick_sanitize(text, effective_user_context)
        else:
            raise LocalModeError("quick_sanitize only available in local mode. Use sanitize() for remote mode.")

    def quick_sanitize_sync(self, text: str, user_context: Optional[UserContext] = None) -> str:
        """Sync version of quick_sanitize."""
        return asyncio.run(self.quick_sanitize(text, user_context))

    async def scan_for_injections(self, text: str) -> list[InjectionDetail]:
        """
        Scan for injections without sanitizing (local mode only).

        Args:
            text: Text to scan

        Returns:
            List of detected injection details
        """
        if self._local_mode:
            if self._core is None:
                raise ConfigurationError("Local core not initialized")
            return self._core.scan_for_injections(text)
        else:
            raise LocalModeError("scan_for_injections only available in local mode")

    def scan_for_injections_sync(self, text: str) -> list[InjectionDetail]:
        """Sync version of scan_for_injections."""
        return asyncio.run(self.scan_for_injections(text))

    async def check_permission(
        self,
        user_context: UserContext,
        required_permissions: list[str],
        required_role: Optional[str] = None,
        required_access_level: Optional[int] = None,
        required_department: Optional[str] = None,
    ) -> PermissionEvaluation:
        """
        Check if user has permission for specific action (local mode only).

        Args:
            user_context: User context
            required_permissions: Required permissions
            required_role: Required role
            required_access_level: Required access level
            required_department: Required department

        Returns:
            PermissionEvaluation result
        """
        if self._local_mode:
            if self._core is None:
                raise ConfigurationError("Local core not initialized")
            return self._core.check_permission(
                user_context,
                required_permissions,
                required_role,
                required_access_level,
                required_department,
            )
        else:
            raise LocalModeError("check_permission only available in local mode")

    def check_permission_sync(
        self,
        user_context: UserContext,
        required_permissions: list[str],
        required_role: Optional[str] = None,
        required_access_level: Optional[int] = None,
        required_department: Optional[str] = None,
    ) -> PermissionEvaluation:
        """Sync version of check_permission."""
        return asyncio.run(
            self.check_permission(user_context, required_permissions, required_role, required_access_level, required_department)
        )

    async def authenticate(self, user_context: Optional[UserContext] = None) -> dict[str, Any]:
        """
        Authenticate with the remote API and get a session token.

        Args:
            user_context: Optional user context

        Returns:
            Dict with token and expires_in
        """
        if self._local_mode:
            raise LocalModeError("authenticate() only available in remote mode")

        client = self._get_async_client()
        payload = AuthRequestPayload(
            api_key=self.config.api_key,
            user_context=user_context or self.config.default_user_context or UserContext(user_id="", tenant_id="", role=""),
        )

        response = await self._execute_with_retry_async(
            lambda: client.post("/auth", json=payload.model_dump())
        )
        data = AuthResponse(**response.json())

        if not data.success:
            raise AuthenticationError(data.error or "Authentication failed")

        self._auth_token = data.data["token"]
        self._token_expiry = time.time() + data.data["expiresIn"]

        return {"token": self._auth_token, "expires_in": data.data["expiresIn"]}

    def authenticate_sync(self, user_context: Optional[UserContext] = None) -> dict[str, Any]:
        """Sync version of authenticate."""
        return asyncio.run(self.authenticate(user_context))

    async def health_check(self) -> HealthResponse:
        """
        Health check - works in both modes.

        Returns:
            HealthResponse with status
        """
        if self._local_mode:
            return HealthResponse(
                status="healthy",
                version="0.2.0",
                timestamp=datetime.utcnow().isoformat() + "Z",
                checks={"core": "ok"},
            )
        else:
            await self._ensure_auth_token()
            client = self._get_async_client()
            headers = self._get_auth_headers()

            response = await self._execute_with_retry_async(
                lambda: client.get("/health", headers=headers)
            )
            return HealthResponse(**response.json())

    def health_check_sync(self) -> HealthResponse:
        """Sync version of health_check."""
        return asyncio.run(self.health_check())

    def get_core(self) -> Optional[InfraLayerCore]:
        """Get the underlying core instance (local mode only)."""
        return self._core if self._local_mode else None

    def set_default_user_context(self, user_context: UserContext) -> None:
        """Update default user context."""
        self.config.default_user_context = user_context

    def with_config(self, overrides: dict[str, Any]) -> InfraLayer:
        """Create a new SDK instance with modified config (for multi-tenant scenarios)."""
        config_dict = self.config.model_dump()
        config_dict.update(overrides)
        new_config = InfraLayerConfig(**config_dict)
        return InfraLayer(new_config)

    async def close(self) -> None:
        """Close HTTP clients."""
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    def close_sync(self) -> None:
        """Sync version of close."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None
        # For async client, we need to run in event loop
        if self._client:
            try:
                asyncio.run(self._client.aclose())
            except RuntimeError:
                # Already in event loop
                pass
            self._client = None

    async def __aenter__(self) -> InfraLayer:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    def __enter__(self) -> InfraLayer:
        """Sync context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Sync context manager exit."""
        self.close_sync()


# Factory functions
def create_infralayer(config: Optional[InfraLayerConfig] = None) -> InfraLayer:
    """Factory function to create an InfraLayer client."""
    return InfraLayer(config)


def create_local_infralayer(
    custom_injection_patterns: Optional[list] = None,
    custom_pii_patterns: Optional[list] = None,
    custom_secret_patterns: Optional[list] = None,
    role_hierarchy: Optional[dict[str, int]] = None,
    custom_rules: Optional[list] = None,
) -> InfraLayer:
    """Create a pre-configured client for local-only usage."""
    core = create_infralayer_core(
        custom_injection_patterns=custom_injection_patterns,
        custom_pii_patterns=custom_pii_patterns,
        custom_secret_patterns=custom_secret_patterns,
        role_hierarchy=role_hierarchy,
        custom_rules=custom_rules,
    )
    return InfraLayer(InfraLayerConfig(local_mode=True, core_instance=core))


def create_remote_infralayer(
    api_url: str,
    api_key: str,
    default_user_context: Optional[UserContext] = None,
    **kwargs: Any,
) -> InfraLayer:
    """Create a pre-configured client for remote API usage."""
    return InfraLayer(
        InfraLayerConfig(
            local_mode=False,
            api_url=api_url,
            api_key=api_key,
            default_user_context=default_user_context,
            **kwargs,
        )
    )