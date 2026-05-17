/**
 * Authentication State Manager for RODiT operations
 * Copyright (c) 2025 Discernible IO. All rights reserved.
 */

const { ulid } = require("ulid");
const { logger, createLogContext, logErrorWithMetrics } = require("../../services/logger");
const utils = require("../../utils");

logger.info("Loading statemanager.js module", {
  component: "AuthStateManager",
  type: "module",
  loadedAt: new Date().toISOString(),
});

/**
 * Singleton class for managing authentication state
 * This includes RODiT configurations, JWT tokens, and public keys
 */
class AuthStateManager {
  constructor() {
    if (AuthStateManager.instance) {
      return AuthStateManager.instance;
    }

    // Separate variables for own key and peer key
    this.ownBase64urlJwkPublicKey = null;
    this.peerBase64urlJwkPublicKey = null;

    // Other existing properties
    this.config_own_rodit = null;
    this.signportalJwtToken = null;
    this.jwtToken = null;

    // Session management
    this.sessions = new Map();

    AuthStateManager.instance = this;
  }

  // Methods for own public key
  async setOwnBase64urlJwkPublicKey(key) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext(
      "AuthStateManager",
      "setOwnBase64urlJwkPublicKey",
      {
        requestId,
        keyLength: key ? key.length : 0,
        keyFirstChars: key ? key.substring(0, 10) + "..." : "null",
      }
    );

    logger.debug("Setting own base64url JWK public key", baseContext);

    try {
      this.ownBase64urlJwkPublicKey = key;

      const duration = Date.now() - startTime;
      logger.debug("Successfully set own base64url JWK public key", {
        ...baseContext,
        duration,
      });

      // Add metric for key operations
      logger.info("auth_key_operations", {
        ...baseContext,
        duration,
        operation: "set",
        keyType: "own",
        result: "success",
      });

      return key;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to set own base64url JWK public key",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_key_operations_error",
        {
          operation: "set",
          keyType: "own",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getOwnBase64urlJwkPublicKey() {
    const requestId = ulid();
    const startTime = Date.now();

    const hasKey = !!this.ownBase64urlJwkPublicKey;
    const baseContext = createLogContext(
      "AuthStateManager",
      "getOwnBase64urlJwkPublicKey",
      {
        requestId,
        hasKey,
        keyLength: hasKey ? this.ownBase64urlJwkPublicKey.length : 0,
      }
    );

    logger.debug("Getting own base64url JWK public key", baseContext);

    try {
      const duration = Date.now() - startTime;

      logger.debug("Retrieved own base64url JWK public key", {
        ...baseContext,
        duration,
      });

      // Add metric for key operations
      logger.info("auth_key_operations", {
        ...baseContext,
        duration,
        operation: "get",
        keyType: "own",
        result: "success",
        hasKey,
      });

      return this.ownBase64urlJwkPublicKey;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get own base64url JWK public key",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_key_operations_error",
        {
          operation: "get",
          keyType: "own",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  // Methods for peer public key
  async setPeerBase64urlJwkPublicKey(key) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext(
      "AuthStateManager",
      "setPeerBase64urlJwkPublicKey",
      {
        requestId,
        keyLength: key ? key.length : 0,
        keyFirstChars: key ? key.substring(0, 10) + "..." : "null",
      }
    );

    logger.debug("Setting peer base64url JWK public key", baseContext);

    try {
      this.peerBase64urlJwkPublicKey = key;

      const duration = Date.now() - startTime;
      logger.debug("Successfully set peer base64url JWK public key", {
        ...baseContext,
        duration,
      });

      // Add metric for key operations
      logger.info("auth_key_operations", {
        ...baseContext,
        duration,
        operation: "set",
        keyType: "peer",
        result: "success",
      });

      return key;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to set peer base64url JWK public key",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_key_operations_error",
        {
          operation: "set",
          keyType: "peer",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getPeerBase64urlJwkPublicKey() {
    const requestId = ulid();
    const startTime = Date.now();

    const hasKey = !!this.peerBase64urlJwkPublicKey;
    const baseContext = createLogContext(
      "AuthStateManager",
      "getPeerBase64urlJwkPublicKey",
      {
        requestId,
        hasKey,
        keyLength: hasKey ? this.peerBase64urlJwkPublicKey.length : 0,
      }
    );

    logger.debug("Getting peer base64url JWK public key", baseContext);

    try {
      const duration = Date.now() - startTime;

      logger.debug("Retrieved peer base64url JWK public key", {
        ...baseContext,
        duration,
      });

      // Add metric for key operations
      logger.info("auth_key_operations", {
        ...baseContext,
        duration,
        operation: "get",
        keyType: "peer",
        result: "success",
        hasKey,
      });

      return this.peerBase64urlJwkPublicKey;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get peer base64url JWK public key",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_key_operations_error",
        {
          operation: "get",
          keyType: "peer",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  // RODiT configuration management
  async setConfigOwnRodit(config) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext(
      "AuthStateManager",
      "setConfigOwnRodit",
      {
        requestId,
        hasConfig: !!config,
      }
    );

    logger.debug("Setting own RODiT configuration", baseContext);

    try {
      // Ensure private key is in Uint8Array format for nacl.sign.detached
      if (config && config.own_rodit_bytes_private_key) {
        const privateKey = config.own_rodit_bytes_private_key;

        // Check if the private key is already a Uint8Array
        if (!(privateKey instanceof Uint8Array)) {
          logger.debug("Converting private key to Uint8Array", {
            ...baseContext,
            privateKeyType: typeof privateKey,
            isBuffer: Buffer.isBuffer(privateKey),
          });

          // Convert Buffer to Uint8Array
          if (Buffer.isBuffer(privateKey)) {
            config.own_rodit_bytes_private_key = new Uint8Array(privateKey);
          }
          // Convert base64/hex string to Uint8Array
          else if (typeof privateKey === "string") {
            try {
              // Try to decode as base64 first
              const buffer = Buffer.from(privateKey, "base64");
              config.own_rodit_bytes_private_key = new Uint8Array(buffer);
            } catch (conversionError) {
              logger.error(
                "Failed to convert private key string to Uint8Array",
                {
                  ...baseContext,
                  error: conversionError.message,
                }
              );
              throw new Error("Private key must be convertible to Uint8Array");
            }
          } else {
            logger.error("Private key is in an unsupported format", {
              ...baseContext,
              privateKeyType: typeof privateKey,
            });
            throw new Error(
              "Private key must be a Buffer, string, or Uint8Array"
            );
          }

          logger.debug("Successfully converted private key to Uint8Array", {
            ...baseContext,
            convertedKeyLength: config.own_rodit_bytes_private_key.length,
          });
        }
      }

      this.config_own_rodit = config;

      const duration = Date.now() - startTime;
      logger.debug("Successfully set own RODiT configuration", {
        ...baseContext,
        duration,
      });

      // Add metric for configuration operations
      logger.info("auth_config_operations", {
        ...baseContext,
        duration,
        operation: "set",
        configType: "own_rodit",
        result: "success",
      });

      return config;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to set own RODiT configuration",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_config_operations_error",
        {
          operation: "set",
          configType: "own_rodit",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getConfigOwnRodit() {
    const requestId = ulid();
    const startTime = Date.now();

    const hasConfig = !!this.config_own_rodit;
    const baseContext = createLogContext(
      "AuthStateManager",
      "getConfigOwnRodit",
      {
        requestId,
        hasConfig,
      }
    );

    logger.debug("Getting own RODiT configuration", baseContext);

    try {
      const duration = Date.now() - startTime;

      logger.debug("Retrieved own RODiT configuration", {
        ...baseContext,
        duration,
      });

      // Add metric for configuration operations
      logger.info("auth_config_operations", {
        ...baseContext,
        duration,
        operation: "get",
        configType: "own_rodit",
        result: "success",
        hasConfig,
      });

      return this.config_own_rodit;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get own RODiT configuration",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_config_operations_error",
        {
          operation: "get",
          configType: "own_rodit",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  // JWT token management
  async setSignPortalJwtToken(token) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext(
      "AuthStateManager",
      "setSignPortalJwtToken",
      {
        requestId,
        hasToken: !!token,
      }
    );

    logger.debug("Setting SignPortal JWT token", baseContext);

    try {
      this.signportalJwtToken = token;

      const duration = Date.now() - startTime;
      logger.debug("Successfully set SignPortal JWT token", {
        ...baseContext,
        duration,
      });

      // Add metric for token operations
      logger.info("auth_token_operations", {
        ...baseContext,
        duration,
        operation: "set",
        tokenType: "signportal",
        result: "success",
      });

      return token;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to set SignPortal JWT token",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_token_operations_error",
        {
          operation: "set",
          tokenType: "signportal",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getSignPortalJwtToken() {
    const requestId = ulid();
    const startTime = Date.now();

    const hasToken = !!this.signportalJwtToken;
    const baseContext = createLogContext(
      "AuthStateManager",
      "getSignPortalJwtToken",
      {
        requestId,
        hasToken,
      }
    );

    logger.debug("Getting SignPortal JWT token", baseContext);

    try {
      const duration = Date.now() - startTime;

      logger.debug("Retrieved SignPortal JWT token", {
        ...baseContext,
        duration,
      });

      // Add metric for token operations
      logger.info("auth_token_operations", {
        ...baseContext,
        duration,
        operation: "get",
        tokenType: "signportal",
        result: "success",
        hasToken,
      });

      return this.signportalJwtToken;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get SignPortal JWT token",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_token_operations_error",
        {
          operation: "get",
          tokenType: "signportal",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  async setJwtToken(token) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "setJwtToken", {
      requestId,
      hasToken: !!token,
    });

    logger.debug("Setting JWT token", baseContext);

    try {
      this.jwtToken = token;

      const duration = Date.now() - startTime;
      logger.debug("Successfully set JWT token", {
        ...baseContext,
        duration,
      });

      // Add metric for token operations
      logger.info("auth_token_operations", {
        ...baseContext,
        duration,
        operation: "set",
        tokenType: "jwt",
        result: "success",
      });

      return token;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to set JWT token",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_token_operations_error",
        {
          operation: "set",
          tokenType: "jwt",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getJwtToken() {
    const requestId = ulid();
    const startTime = Date.now();

    const hasToken = !!this.jwtToken;
    const baseContext = createLogContext("AuthStateManager", "getJwtToken", {
      requestId,
      hasToken,
    });

    logger.debug("Getting JWT token", baseContext);

    try {
      const duration = Date.now() - startTime;

      logger.debug("Retrieved JWT token", {
        ...baseContext,
        duration,
      });

      // Add metric for token operations
      logger.info("auth_token_operations", {
        ...baseContext,
        duration,
        operation: "get",
        tokenType: "jwt",
        result: "success",
        hasToken,
      });

      return this.jwtToken;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get JWT token",
        {
          ...baseContext,
          duration,
        },
        error,
        "auth_token_operations_error",
        {
          operation: "get",
          tokenType: "jwt",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  // Session management
  createSession(sessionData) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "createSession", {
      requestId,
      sessionId: sessionData?.id,
    });

    logger.debug("Creating new session", baseContext);

    try {
      if (!sessionData || !sessionData.id) {
        const error = new Error("Session data must include an ID");

        logErrorWithMetrics(
          "Failed to create session: missing ID",
          baseContext,
          error,
          "session_operations_error",
          {
            operation: "create",
            result: "error",
            reason: "missing_id",
          }
        );

        throw error;
      }

      const sessionWithTimestamp = {
        ...sessionData,
        lastAccessedAt: Math.floor(Date.now() / 1000),
      };

      this.sessions.set(sessionData.id, sessionWithTimestamp);

      const duration = Date.now() - startTime;
      logger.debug("Successfully created session", {
        ...baseContext,
        duration,
        sessionData: {
          id: sessionData.id,
          lastAccessedAt: sessionWithTimestamp.lastAccessedAt,
        },
      });

      // Add metric for session operations
      logger.info("session_operations", {
        ...baseContext,
        duration,
        operation: "create",
        result: "success",
      });

      return sessionWithTimestamp;
    } catch (error) {
      if (error.message !== "Session data must include an ID") {
        const duration = Date.now() - startTime;

        logErrorWithMetrics(
          "Failed to create session",
          {
            ...baseContext,
            duration,
          },
          error,
          "session_operations_error",
          {
            operation: "create",
            result: "error",
            duration,
          }
        );
      }

      throw error;
    }
  }

  getSession(sessionId) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "getSession", {
      requestId,
      sessionId,
    });

    logger.debug("Getting session", baseContext);

    try {
      const session = this.sessions.get(sessionId);
      const hasSession = !!session;

      const duration = Date.now() - startTime;
      logger.debug("Session retrieval complete", {
        ...baseContext,
        duration,
        found: hasSession,
      });

      // Add metric for session operations
      logger.info("session_operations", {
        ...baseContext,
        duration,
        operation: "get",
        result: "success",
        found: hasSession,
      });

      return session;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get session",
        {
          ...baseContext,
          duration,
        },
        error,
        "session_operations_error",
        {
          operation: "get",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  updateSession(sessionId, updates) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "updateSession", {
      requestId,
      sessionId,
    });

    logger.debug("Updating session", baseContext);

    try {
      if (!this.sessions.has(sessionId)) {
        const duration = Date.now() - startTime;

        logger.warn("Session not found for update", {
          ...baseContext,
          duration,
        });

        // Add metric for session operations
        logger.info("session_operations", {
          ...baseContext,
          duration,
          operation: "update",
          result: "not_found",
        });

        return null;
      }

      const session = this.sessions.get(sessionId);
      const updatedSession = {
        ...session,
        ...updates,
        lastAccessedAt: Math.floor(Date.now() / 1000),
      };

      this.sessions.set(sessionId, updatedSession);

      const duration = Date.now() - startTime;
      logger.debug("Successfully updated session", {
        ...baseContext,
        duration,
      });

      // Add metric for session operations
      logger.info("session_operations", {
        ...baseContext,
        duration,
        operation: "update",
        result: "success",
      });

      return updatedSession;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to update session",
        {
          ...baseContext,
          duration,
        },
        error,
        "session_operations_error",
        {
          operation: "update",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  deleteSession(sessionId) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "deleteSession", {
      requestId,
      sessionId,
    });

    logger.debug("Deleting session", baseContext);

    try {
      if (!this.sessions.has(sessionId)) {
        const duration = Date.now() - startTime;

        logger.warn("Session not found for deletion", {
          ...baseContext,
          duration,
        });

        // Add metric for session operations
        logger.info("session_operations", {
          ...baseContext,
          duration,
          operation: "delete",
          result: "not_found",
        });

        return false;
      }

      const deleted = this.sessions.delete(sessionId);

      const duration = Date.now() - startTime;
      logger.debug("Session deletion complete", {
        ...baseContext,
        duration,
        deleted,
      });

      // Add metric for session operations
      logger.info("session_operations", {
        ...baseContext,
        duration,
        operation: "delete",
        result: deleted ? "success" : "failed",
      });

      return deleted;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to delete session",
        {
          ...baseContext,
          duration,
        },
        error,
        "session_operations_error",
        {
          operation: "delete",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getAllSessions() {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "getAllSessions", {
      requestId,
    });

    logger.debug("Getting all sessions", baseContext);

    try {
      const sessions = Array.from(this.sessions.values());

      const duration = Date.now() - startTime;
      logger.debug("Retrieved all sessions", {
        ...baseContext,
        duration,
        sessionCount: sessions.length,
      });

      // Add metric for session operations
      logger.info("session_operations", {
        ...baseContext,
        duration,
        operation: "getAll",
        result: "success",
        sessionCount: sessions.length,
      });

      return sessions;
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Failed to get all sessions",
        {
          ...baseContext,
          duration,
        },
        error,
        "session_operations_error",
        {
          operation: "getAll",
          result: "error",
          duration,
        }
      );

      throw error;
    }
  }

  getPortalUrl(serviceProviderId, port) {
    const requestId = ulid();
    const startTime = Date.now();

    const baseContext = createLogContext("AuthStateManager", "getPortalUrl", {
      requestId,
      serviceProviderId,
      port,
    });

    logger.debug("Generating portal URL", baseContext);

    try {
      // Validate serviceProviderId
      if (!serviceProviderId) {
        const error = new Error(
          "serviceProviderId is undefined in getPortalUrl"
        );

        logErrorWithMetrics(
          "Missing serviceProviderId parameter",
          baseContext,
          error,
          "portal_url_error",
          {
            result: "error",
            reason: "missing_provider_id",
          }
        );

        throw error;
      }

      // Extract smart contract component from serviceprovider_id
      const components = serviceProviderId.split(";");
      const scComponent = components
        .find((c) => c.startsWith("sc="))
        ?.substring(3);

      if (!scComponent) {
        const error = new Error(
          "Invalid serviceprovider_id format: missing sc= component"
        );

        logErrorWithMetrics(
          "Invalid serviceprovider_id format",
          {
            ...baseContext,
            serviceProviderId,
          },
          error,
          "portal_url_error",
          {
            result: "error",
            reason: "invalid_format",
          }
        );

        throw error;
      }

      // Extract domain parts from smart contract name
      const scParts = scComponent.split(".");
      if (scParts.length < 1) {
        const error = new Error("Invalid smart contract format");

        logErrorWithMetrics(
          "Invalid smart contract format",
          {
            ...baseContext,
            serviceProviderId,
            scComponent,
          },
          error,
          "portal_url_error",
          {
            result: "error",
            reason: "invalid_sc_format",
          }
        );

        throw error;
      }

      // Get domain information from the first part
      const domainPart = scParts[0];
      const domainComponents = domainPart.split("-");

      // Find domain and TLD in the components (format: 10975-discernible-org)
      if (domainComponents.length < 3) {
        const error = new Error("Invalid domain format in smart contract");

        logErrorWithMetrics(
          "Invalid domain format in smart contract",
          {
            ...baseContext,
            serviceProviderId,
            scComponent,
            domainPart,
          },
          error,
          "portal_url_error",
          {
            result: "error",
            reason: "invalid_domain_format",
          }
        );

        throw error;
      }

      const domain = domainComponents[1]; // discernible
      const tld = domainComponents[2]; // org

      // Build the API endpoint
      const portalUrl = `https://signportal.${domain}.${tld}:${port}`;

      const duration = Date.now() - startTime;
      logger.debug("Successfully generated portal URL", {
        ...baseContext,
        duration,
        portalUrl,
      });

      // Add metric for portal URL generation
      logger.info("portal_url_operations", {
        ...baseContext,
        duration,
        result: "success",
      });

      return portalUrl;
    } catch (error) {
      const duration = Date.now() - startTime;

      // Only log errors that haven't been logged already
      if (!error.logged) {
        logErrorWithMetrics(
          "Unexpected error generating portal URL",
          {
            ...baseContext,
            duration,
          },
          error,
          "portal_url_error",
          {
            result: "error",
            reason: "unexpected",
            duration,
          }
        );
      }

      throw error;
    }
  }

  /**
   * Performs a fetch operation with comprehensive error handling and logging for Grafana monitoring
   *
   * @param {string} url - The URL to fetch from
   * @param {Object} options - Fetch options including method, headers, etc.
   * @returns {Promise<Object>} - The response data or error object
   */
  async fetchWithErrorHandling(url, options, retryCount = 0) {
    const requestId = ulid();
    const startTime = Date.now();
    const operation = options?.method || "POST";
    const urlObj = new URL(url);
    const endpoint = urlObj.pathname;
    const MAX_AUTH_RETRIES = 1; // Retries for expired tokens
    const MAX_RATE_LIMIT_RETRIES = 3; // Retries for rate limiting

    logger.debug("API request initiated", {
      component: "APIClient",
      method: "fetchWithErrorHandling",
      requestId,
      url: endpoint,
      operation,
      retryCount,
    });

    try {
      // Get the current JWT token for authentication
      const jwt_token = this.getJwtToken();

      // Add authorization and tracking headers
      options.headers = {
        ...options.headers,
        ...(jwt_token ? { Authorization: `Bearer ${jwt_token}` } : {}),
        "X-Request-ID": requestId,
      };

      // Make the API request
      const response = await fetch(url, options);
      const responseTime = Date.now() - startTime;

      // Check for a renewed token in response headers
      const newToken = response.headers.get("New-Token");
      if (newToken) {
        try {
          await this.setJwtToken(newToken);
          logger.debug("JWT token refreshed from header", {
            component: "APIClient",
            method: "fetchWithErrorHandling",
            requestId,
          });
        } catch (tokenError) {
          logger.debug("Failed to update JWT token", {
            component: "APIClient",
            method: "fetchWithErrorHandling",
            requestId,
            error: tokenError.message,
          });
        }
      }

      // Record response time metrics
      logger.debug("api_request_duration_milliseconds", responseTime, {
        endpoint,
        method: operation,
        status: response.status,
      });

      // Handle 401 Unauthorized with retry for token expiration
      if (response.status === 401 && retryCount < MAX_AUTH_RETRIES) {
        const responseData = await response.json();

        // Only retry for expired tokens
        if (responseData.error && responseData.error.code === "TOKEN_EXPIRED") {
          logger.debug("Token expired, attempting login refresh", {
            component: "APIClient",
            method: "fetchWithErrorHandling",
            requestId,
          });

          // Try to login again to get a fresh token
          // This implementation depends on your authentication flow
          try {
            const config_own_rodit = this.getConfigOwnRodit();
            if (config_own_rodit && config_own_rodit.own_rodit) {
              const loginResult = await login_server(config_own_rodit);

              if (loginResult && loginResult.jwt_token) {
                // Save the new token
                await this.setJwtToken(loginResult.jwt_token);

                // Retry the request with the new token
                return this.fetchWithErrorHandling(
                  url,
                  options,
                  retryCount + 1
                );
              }
            }
          } catch (loginError) {
            logger.debug("Failed to refresh token through login", {
              component: "APIClient",
              method: "fetchWithErrorHandling",
              requestId,
              error: loginError.message,
            });
          }
        }
      }

      // Handle 429 Too Many Requests with retry and exponential backoff
      if (response.status === 429 && retryCount < MAX_RATE_LIMIT_RETRIES) {
        // Get retry-after header or default to exponential backoff
        const retryAfter = response.headers.get("Retry-After");
        let waitTime = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : Math.pow(2, retryCount) * 1000;

        // Cap the wait time at 30 seconds
        waitTime = Math.min(waitTime, 30000);

        // Log rate limiting information
        logger.warn("Rate limit exceeded", {
          component: "APIClient",
          method: "fetchWithErrorHandling",
          requestId,
          url: endpoint,
          statusCode: response.status,
          retryCount,
          retryAfter: retryAfter || "not specified",
          waitTime: waitTime / 1000,
          event: "rate_limit_exceeded",
          maxRequests: response.headers.get("X-RateLimit-Limit"),
          windowMinutes: response.headers.get("X-RateLimit-Window") || 15,
        });

        // Record rate limit metric
        logger.info("api_rate_limit_exceeded_total", {
          ...baseContext,
          count: 1,
          endpoint,
          method: operation,
        });

        // Wait for the specified time before retrying
        await new Promise((resolve) => setTimeout(resolve, waitTime));

        // Retry the request
        return this.fetchWithErrorHandling(url, options, retryCount + 1);
      }

      // Parse response as JSON for all status codes
      let responseData;
      try {
        responseData = await response.json();
      } catch (parseError) {
        // Handle non-JSON responses
        const text = await response.text();
        responseData = {
          rawResponse: text.substring(0, 100), // Only include a preview
          parseError: parseError.message,
        };
      }

      if (!response.ok) {
        // Handle error responses
        logger.debug("API request failed", {
          component: "APIClient",
          method: "fetchWithErrorHandling",
          requestId,
          url: endpoint,
          statusCode: response.status,
          errorDetails: responseData,
        });

        // Record error metrics
        logger.debug("api_request_errors_total", 1, {
          endpoint,
          method: operation,
          status: response.status,
        });

        return {
          error: responseData.error || "RequestFailed",
          message:
            responseData.message || `Request failed: ${response.statusText}`,
          statusCode: response.status,
          details: responseData,
        };
      }

      // Log successful request
      logger.debug("API request completed", {
        component: "APIClient",
        method: "fetchWithErrorHandling",
        requestId,
        url: endpoint,
        statusCode: response.status,
        duration: responseTime,
      });

      return responseData;
    } catch (error) {
      const errorDuration = Date.now() - startTime;

      // Log detailed error information
      logger.debug("Fetch operation failed", {
        component: "APIClient",
        method: "fetchWithErrorHandling",
        requestId,
        url: endpoint,
        errorMessage: error.message,
        errorStack: error.stack,
        duration: errorDuration,
      });

      // Return a standardized error object
      return {
        error: "RequestFailed",
        message: error.message,
        isNetworkError:
          error.message.includes("fetch") || error.message.includes("network"),
      };
    }
  }

  /**
   * Performs a fetch operation with comprehensive error handling and logging for Grafana monitoring
   *
   * @param {string} url - The URL to fetch from
   * @param {Object} options - Fetch options including method, headers, etc.
   * @returns {Promise<Object>} - The response data or error object
   */
  async fetchWithErrorHandlingSignPortal(url, options, retryCount = 0) {
    const requestId = ulid();
    const startTime = Date.now();
    const operation = options?.method || "POST";
    const urlObj = new URL(url);
    const endpoint = urlObj.pathname;
    const MAX_RETRIES = 1; // Only retry once for expired tokens

    logger.debug("API request initiated", {
      component: "APIClient",
      method: "fetchWithErrorHandling",
      requestId,
      url: endpoint,
      operation,
      retryCount,
    });

    try {
      // Get the current JWT token for authentication
      const jwt_token = this.getSignPortalJwtToken();

      // Add authorization and tracking headers
      options.headers = {
        ...options.headers,
        ...(jwt_token ? { Authorization: `Bearer ${jwt_token}` } : {}),
        "X-Request-ID": requestId,
      };

      // Make the API request
      const response = await fetch(url, options);
      const responseTime = Date.now() - startTime;

      // Check for a renewed token in response headers
      const newToken = response.headers.get("New-Token");
      if (newToken) {
        try {
          await this.setSignPortalJwtToken(newToken);
          logger.debug("JWT token refreshed from header", {
            component: "APIClient",
            method: "fetchWithErrorHandling",
            requestId,
          });
        } catch (tokenError) {
          logger.debug("Failed to update JWT token", {
            component: "APIClient",
            method: "fetchWithErrorHandling",
            requestId,
            error: tokenError.message,
          });
        }
      }

      // Record response time metrics
      logger.debug("api_request_duration_milliseconds", responseTime, {
        endpoint,
        method: operation,
        status: response.status,
      });

      // Handle 401 Unauthorized with retry for token expiration
      if (response.status === 401 && retryCount < MAX_RETRIES) {
        const responseData = await response.json();

        // Only retry for expired tokens
        if (responseData.error && responseData.error.code === "TOKEN_EXPIRED") {
          logger.debug("Token expired, attempting login refresh", {
            component: "APIClient",
            method: "fetchWithErrorHandling",
            requestId,
          });

          // Try to login again to get a fresh token
          // This implementation depends on your authentication flow
          try {
            const config_own_rodit = stateManager.getConfigOwnRodit();
            if (config_own_rodit && config_own_rodit.own_rodit) {
              const loginResult = await login_server(config_own_rodit);

              if (loginResult && loginResult.jwt_token) {
                // Save the new token
                await this.setSignPortalJwtToken(loginResult.jwt_token);

                // Retry the request with the new token
                return this.fetchWithErrorHandlingSignPortal(
                  url,
                  options,
                  retryCount + 1
                );
              }
            }
          } catch (loginError) {
            logger.debug("Failed to refresh token through login", {
              component: "APIClient",
              method: "fetchWithErrorHandling",
              requestId,
              error: loginError.message,
            });
          }
        }
      }

      // Parse response as JSON for all status codes
      let responseData;
      try {
        responseData = await response.json();
      } catch (parseError) {
        // Handle non-JSON responses
        const text = await response.text();
        responseData = {
          rawResponse: text.substring(0, 100), // Only include a preview
          parseError: parseError.message,
        };
      }

      if (!response.ok) {
        // Handle error responses
        logger.debug("API request failed", {
          component: "APIClient",
          method: "fetchWithErrorHandling",
          requestId,
          url: endpoint,
          statusCode: response.status,
          errorDetails: responseData,
        });

        // Record error metrics
        logger.debug("api_request_errors_total", 1, {
          endpoint,
          method: operation,
          status: response.status,
        });

        return {
          error: responseData.error || "RequestFailed",
          message:
            responseData.message || `Request failed: ${response.statusText}`,
          statusCode: response.status,
          details: responseData,
        };
      }

      // Log successful request
      logger.debug("API request completed", {
        component: "APIClient",
        method: "fetchWithErrorHandling",
        requestId,
        url: endpoint,
        statusCode: response.status,
        duration: responseTime,
      });

      return responseData;
    } catch (error) {
      const errorDuration = Date.now() - startTime;

      // Log detailed error information
      logger.debug("Fetch operation failed", {
        component: "APIClient",
        method: "fetchWithErrorHandling",
        requestId,
        url: endpoint,
        errorMessage: error.message,
        errorStack: error.stack,
        duration: errorDuration,
      });

      // Return a standardized error object
      return {
        error: "RequestFailed",
        message: error.message,
        isNetworkError:
          error.message.includes("fetch") || error.message.includes("network"),
      };
    }
  }
}

// Create and export a singleton instance
const stateManager = new AuthStateManager();
module.exports = stateManager;
