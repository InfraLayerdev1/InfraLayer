/**
 * @fileoverview InfraLayer TypeScript/Node SDK
 * Client for pre-LLM security filtering, sanitization, and telemetry.
 * Supports both local (in-process) and remote (API) modes.
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosError } from 'axios';
import {
  InfraLayerCore,
  createInfraLayerCore,
  UserContext,
  RawContext,
  SanitizedContext,
  SanitizeOptions,
  SanitizeResult,
  PermissionEvaluation,
  InjectionDetail,
  InjectionPattern,
  SecurityFlag,
  SanitizeTelemetry
} from 'infralayer-core';

// Re-export core types for convenience
export type {
  UserContext,
  RawContext,
  SanitizedContext,
  SanitizeOptions,
  SanitizeResult,
  PermissionEvaluation,
  InjectionDetail,
  InjectionPattern,
  SecurityFlag,
  SanitizeTelemetry
};

/**
 * Configuration options for the InfraLayer SDK client
 */
export interface InfraLayerConfig {
  /** API base URL for remote mode (e.g., 'https://api.infralayer.io/v1') */
  apiUrl?: string;
  /** API key for remote authentication */
  apiKey?: string;
  /** Default user context to use for all requests */
  defaultUserContext?: UserContext;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Maximum number of retry attempts for failed requests */
  maxRetries?: number;
  /** Base delay for exponential backoff (ms) */
  retryBaseDelay?: number;
  /** Enable local mode (uses @infralayer/core in-process) */
  localMode?: boolean;
  /** Custom core instance for local mode */
  coreInstance?: InfraLayerCore;
  /** Custom axios instance for advanced configuration */
  axiosInstance?: AxiosInstance;
  /** Callback for request/response logging */
  onRequest?: (config: AxiosRequestConfig) => void;
  onResponse?: (response: any) => void;
  onError?: (error: Error) => void;
}

/**
 * Request payload for the /v1/sanitize endpoint
 */
export interface SanitizeRequestPayload {
  userContext: UserContext;
  rawContext: RawContext | RawContext[];
  options?: SanitizeOptions['options'];
}

/**
 * Response from the /v1/sanitize endpoint
 */
export interface SanitizeResponse {
  success: boolean;
  data?: SanitizeResult;
  error?: string;
  meta?: {
    requestId: string;
    timestamp: string;
    processingTimeMs: number;
  };
}

/**
 * Request payload for the /v1/auth endpoint
 */
export interface AuthRequestPayload {
  apiKey: string;
  userContext: UserContext;
}

/**
 * Response from the /v1/auth endpoint
 */
export interface AuthResponse {
  success: boolean;
  data?: {
    token: string;
    expiresIn: number;
    userContext: UserContext;
  };
  error?: string;
}

/**
 * Health check response
 */
export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  timestamp: string;
  checks: {
    core: 'ok' | 'error';
    api?: 'ok' | 'error';
  };
}

/**
 * InfraLayer SDK Client Class
 * Provides both local (in-process) and remote (API) sanitization capabilities
 */
export class InfraLayer {
  private config: Required<InfraLayerConfig>;
  private axios: AxiosInstance;
  private core: InfraLayerCore;
  private authToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor(config: InfraLayerConfig = {}) {
    this.config = {
      apiUrl: config.apiUrl || 'https://api.infralayer.io/v1',
      apiKey: config.apiKey || '',
      defaultUserContext: config.defaultUserContext ?? null,
      timeout: config.timeout || 30000,
      maxRetries: config.maxRetries || 3,
      retryBaseDelay: config.retryBaseDelay || 1000,
      localMode: config.localMode ?? true, // Default to local mode
      coreInstance: config.coreInstance ?? null,
      axiosInstance: config.axiosInstance ?? null,
      onRequest: config.onRequest ?? (() => {}),
      onResponse: config.onResponse ?? (() => {}),
      onError: config.onError ?? (() => {})
    } as Required<InfraLayerConfig>;

    // Initialize axios instance
    this.axios = this.config.axiosInstance || axios.create({
      baseURL: this.config.apiUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `@infralayer/sdk@0.2.0`
      }
    });

    // Add request/response interceptors
    this.setupInterceptors();

    // Initialize local core if in local mode
    if (this.config.localMode) {
      this.core = this.config.coreInstance || createInfraLayerCore();
    } else {
      this.core = null as any; // Will not be used in remote mode
    }
  }

  /**
   * Setup axios interceptors for auth, retry, and logging
   */
  private setupInterceptors(): void {
    // Request interceptor - inject auth header
    this.axios.interceptors.request.use(async (config) => {
      // Add auth token if available
      if (this.authToken && Date.now() < this.tokenExpiry) {
        config.headers.Authorization = `Bearer ${this.authToken}`;
      } else if (this.config.apiKey) {
        config.headers['x-api-key'] = this.config.apiKey;
      }

      // Call request hook
      this.config.onRequest(config);
      return config;
    });

    // Response interceptor - handle errors and logging
    this.axios.interceptors.response.use(
      (response) => {
        this.config.onResponse(response);
        return response;
      },
      async (error: AxiosError) => {
        this.config.onError(error);

        // Handle 401 - token expired, try to refresh
        if (error.response?.status === 401 && this.config.apiKey) {
          await this.refreshAuthToken();
          // Retry original request with new token
          if (error.config) {
            error.config.headers.Authorization = `Bearer ${this.authToken}`;
            return this.axios.request(error.config);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  /**
   * Refresh authentication token using API key
   */
  private async refreshAuthToken(): Promise<void> {
    try {
      const response = await this.axios.post<AuthResponse>('/auth', {
        apiKey: this.config.apiKey,
        userContext: this.config.defaultUserContext
      });

      if (response.data.success && response.data.data) {
        this.authToken = response.data.data.token;
        this.tokenExpiry = Date.now() + (response.data.data.expiresIn * 1000);
      }
    } catch (err) {
      console.error('Failed to refresh auth token:', err);
      throw new Error('Authentication failed');
    }
  }

  /**
   * Execute with retry logic and exponential backoff
   */
  private async executeWithRetry<T>(
    operation: () => Promise<T>,
    retries: number = this.config.maxRetries
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (retries <= 0) throw error;

      const isRetryable = this.isRetryableError(error);
      if (!isRetryable) throw error;

      const delay = this.config.retryBaseDelay * Math.pow(2, this.config.maxRetries - retries);
      await this.sleep(delay);
      return this.executeWithRetry(operation, retries - 1);
    }
  }

  /**
   * Check if error is retryable
   */
  private isRetryableError(error: any): boolean {
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
      return true;
    }
    if (error.response?.status === 429 || error.response?.status >= 500) {
      return true;
    }
    return false;
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Main sanitize method - works in both local and remote modes
   */
  async sanitize(
    rawContext: RawContext | RawContext[],
    userContext?: UserContext,
    options?: SanitizeOptions['options']
  ): Promise<SanitizeResult> {
    const effectiveUserContext = userContext || this.config.defaultUserContext;
    if (!effectiveUserContext) {
      throw new Error('User context is required. Provide it in the call or set defaultUserContext in config.');
    }

    if (this.config.localMode) {
      return this.sanitizeLocal(rawContext, effectiveUserContext, options);
    } else {
      return this.sanitizeRemote(rawContext, effectiveUserContext, options);
    }
  }

  /**
   * Local in-process sanitization using @infralayer/core
   */
  private sanitizeLocal(
    rawContext: RawContext | RawContext[],
    userContext: UserContext,
    options?: SanitizeOptions['options']
  ): SanitizeResult {
    return this.core.sanitize({
      userContext,
      rawContext,
      options
    });
  }

  /**
   * Remote API sanitization
   */
  private async sanitizeRemote(
    rawContext: RawContext | RawContext[],
    userContext: UserContext,
    options?: SanitizeOptions['options']
  ): Promise<SanitizeResult> {
    const payload: SanitizeRequestPayload = { userContext, rawContext, options };

    const response = await this.executeWithRetry(() =>
      this.axios.post<SanitizeResponse>('/sanitize', payload)
    );

    if (!response.data.success) {
      throw new Error(response.data.error || 'Sanitization failed');
    }

    return response.data.data!;
  }

  /**
   * Quick sanitize for simple use cases
   */
  quickSanitize(text: string, userContext?: UserContext): string {
    const effectiveUserContext = userContext || this.config.defaultUserContext;
    if (!effectiveUserContext) {
      throw new Error('User context is required');
    }

    if (this.config.localMode) {
      return this.core.quickSanitize(text, effectiveUserContext);
    } else {
      throw new Error('quickSanitize only available in local mode. Use sanitize() for remote mode.');
    }
  }

  /**
   * Scan for injections without sanitizing
   */
  scanForInjections(text: string): InjectionDetail[] {
    if (this.config.localMode) {
      return this.core.scanForInjections(text);
    } else {
      throw new Error('scanForInjections only available in local mode');
    }
  }

  /**
   * Check if user has permission for specific action
   */
  checkPermission(
    userContext: UserContext,
    requiredPermissions: string[],
    requiredRole?: string,
    requiredAccessLevel?: number,
    requiredDepartment?: string
  ): PermissionEvaluation {
    if (this.config.localMode) {
      return this.core.checkPermission(userContext, requiredPermissions, requiredRole, requiredAccessLevel, requiredDepartment);
    } else {
      throw new Error('checkPermission only available in local mode');
    }
  }

  /**
   * Authenticate with the remote API and get a session token
   */
  async authenticate(userContext?: UserContext): Promise<{ token: string; expiresIn: number }> {
    if (this.config.localMode) {
      throw new Error('authenticate() only available in remote mode');
    }

    const response = await this.axios.post<AuthResponse>('/auth', {
      apiKey: this.config.apiKey,
      userContext: userContext || this.config.defaultUserContext
    });

    if (!response.data.success) {
      throw new Error(response.data.error || 'Authentication failed');
    }

    this.authToken = response.data.data!.token;
    this.tokenExpiry = Date.now() + (response.data.data!.expiresIn * 1000);

    return {
      token: this.authToken,
      expiresIn: response.data.data!.expiresIn
    };
  }

  /**
   * Health check - works in both modes
   */
  async healthCheck(): Promise<HealthResponse> {
    if (this.config.localMode) {
      return {
        status: 'healthy',
        version: '0.2.0',
        timestamp: new Date().toISOString(),
        checks: { core: 'ok' }
      };
    } else {
      const response = await this.axios.get<HealthResponse>('/health');
      return response.data;
    }
  }

  /**
   * Get the underlying core instance (local mode only)
   */
  getCore(): InfraLayerCore | null {
    return this.config.localMode ? this.core : null;
  }

  /**
   * Switch between local and remote mode
   */
  setMode(localMode: boolean): void {
    this.config.localMode = localMode;
    if (localMode && !this.core) {
      this.core = this.config.coreInstance || createInfraLayerCore();
    }
  }

  /**
   * Update default user context
   */
  setDefaultUserContext(userContext: UserContext): void {
    this.config.defaultUserContext = userContext;
  }

  /**
   * Create a new SDK instance with modified config (for multi-tenant scenarios)
   */
  withConfig(overrides: Partial<InfraLayerConfig>): InfraLayer {
    return new InfraLayer({ ...this.config, ...overrides });
  }
}

/**
 * Factory function to create an InfraLayer client
 */
export function createInfraLayer(config?: InfraLayerConfig): InfraLayer {
  return new InfraLayer(config);
}

/**
 * Create a pre-configured client for local-only usage
 */
export function createLocalInfraLayer(coreConfig?: Parameters<typeof createInfraLayerCore>[0]): InfraLayer {
  return new InfraLayer({
    localMode: true,
    coreInstance: createInfraLayerCore(coreConfig)
  });
}

/**
 * Create a pre-configured client for remote API usage
 */
export function createRemoteInfraLayer(apiUrl: string, apiKey: string, defaultUserContext?: UserContext): InfraLayer {
  return new InfraLayer({
    localMode: false,
    apiUrl,
    apiKey,
    defaultUserContext
  });
}

// Default export
export default InfraLayer;