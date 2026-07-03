/**
 * Authentication middleware for web API
 * Copyright (c) 2026 Discernible IO. All rights reserved.
 */

const { ulid } = require("ulid");
const config = require('../../services/configsdk');
const { isStrictEnvironment } = require('../../services/env');
const logger = require("../../services/logger");
const { sendError } = require("../../services/error-response");
const { createLogContext, logErrorWithMetrics } = logger;
const nacl = require("tweetnacl");
// Import specific functions directly to avoid circular dependencies
const { 
  validate_jwt_token_be,
  generate_jwt_token,
  tokenService
} = require("../auth/tokenservice");
// Import specific functions from authentication.js to avoid circular dependencies
// Import specific functions from authentication.js to avoid circular dependencies
const { 
  resolve_peer_rodit_for_login,
  verify_peer_rodit,
  verify_rodit_ownership_withnep413
} = require("../auth/authentication");
const { 
  nearorg_rpc_tokenfromroditid
} = require("../blockchain/blockchainservice");
// Direct import from statemanager to avoid circular dependencies
const stateManager = require("../blockchain/statemanager");
const utils = require("../../services/utils");
const { unixTimeToDateString } = utils;
// Import sessionManager singleton - ensure we get the same instance used everywhere
const { sessionManager } = require("../auth/sessionmanager");

// Log which SessionManager instance is being used
logger.infoWithContext("AuthenticationMW using SessionManager instance", {
  component: "AuthenticationMW",
  event: "sessionManager_import",
  sessionManagerInstanceId: sessionManager._instanceId,
  timestamp: new Date().toISOString()
});

// Dynamic import for ESM 'jose' in CommonJS context
let _josePromise;
async function getJose() {
  if (!_josePromise) {
    _josePromise = import("jose");
  }
  return _josePromise;
}

// Portal/outbound login only: skip server session registration when relaxed (default).
// API auth does not pass these options and always enforces stored session + expiresAt.
const RELAXED_SESSION_VALIDATION_OPTIONS = Object.freeze({
  enforceSessionRegistration: !config.get(
    "SECURITY_OPTIONS.RELAXED_SESSION_VALIDATION",
    true
  ),
});

// Import validation utilities or define them if not available
const validationResult = { isEmpty: () => true }; // Default implementation if not available

/**
 * Verify sessionManager is properly initialized
 * @throws {Error} If sessionManager is not properly initialized
 */
function verifySessionManager() {
  if (!sessionManager || !sessionManager.storage) {
    throw new Error("SessionManager not properly initialized in authentication middleware");
  }
}

/**
 * Middleware for handling authentication in routes
 */

/**
 * Authenticates a client using RODiT credentials and generates a JWT jwt_token
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Object} - JSON response with jwt_token or error
 */
function normalizeOptionalLoginString(v) {
  if (v === undefined || v === null) {
    return "";
  }
  return String(v).trim();
}

/** Legacy login payload keys that must not appear (wire compat uses roditid_base64url_signature alias below). */
function loginBodyHasDeprecatedKeys(body) {
  if (!body || typeof body !== "object") {
    return false;
  }
  return (
    Object.prototype.hasOwnProperty.call(body, "signature") ||
    Object.prototype.hasOwnProperty.call(body, "account_id")
  );
}

/** Both modern and legacy signature field names filled — ambiguous; login_server sends only legacy field name. */
function loginBodyHasDuplicateSignatureFields(body) {
  if (!body || typeof body !== "object") {
    return false;
  }
  const a =
    typeof body.base64url_signature === "string"
      ? body.base64url_signature.trim()
      : "";
  const b =
    typeof body.roditid_base64url_signature === "string"
      ? body.roditid_base64url_signature.trim()
      : "";
  return a.length > 0 && b.length > 0;
}

function extractLoginBase64UrlSignature(body) {
  const fromNew =
    typeof body.base64url_signature === "string"
      ? body.base64url_signature.trim()
      : "";
  const fromLegacy =
    typeof body.roditid_base64url_signature === "string"
      ? body.roditid_base64url_signature.trim()
      : "";
  return fromNew || fromLegacy;
}

function parseRequiredLoginTimestamp(rawTimestamp) {
  if (rawTimestamp === undefined || rawTimestamp === null || rawTimestamp === "") {
    return null;
  }
  const parsed = Number(rawTimestamp);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function parseRequiredServerLoginTimestamp(rawTimestamp) {
  const parsed = Number(rawTimestamp);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function normalizeOptionalServerAccountId(rawAccountId) {
  if (rawAccountId === undefined || rawAccountId === null) {
    return "";
  }
  return String(rawAccountId).trim();
}

function buildLoginUrl(apiendpoint, loginPath = "/api/login") {
  return `${String(apiendpoint).replace(/\/$/, "")}${loginPath.startsWith("/") ? loginPath : `/${loginPath}`}`;
}

async function resolveServerLoginTimestamp(apiendpoint, options = {}) {
  const explicit = parseRequiredServerLoginTimestamp(options.timestamp);
  if (explicit !== null) {
    return { timestamp: explicit };
  }

  const timestampPath =
    options.timestampPath ??
    config.get("LOGIN_TIMESTAMP_PATH", "/api/login/timestamp");
  const timestampUrl = buildLoginUrl(apiendpoint, timestampPath);

  try {
    const response = await fetch(timestampUrl, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "User-Agent": "RODiT-SDK",
      },
    });

    if (!response.ok) {
      return {
        timestamp: null,
        errorCode: "LOGIN_TIMESTAMP_FETCH_FAILED",
        error: `Failed to fetch login timestamp challenge: HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    const parsed = parseRequiredServerLoginTimestamp(data?.timestamp);
    if (parsed === null) {
      return {
        timestamp: null,
        errorCode: "INVALID_LOGIN_TIMESTAMP",
        error: "Login timestamp challenge response is missing a valid timestamp",
      };
    }

    return { timestamp: parsed };
  } catch (error) {
    return {
      timestamp: null,
      errorCode: "LOGIN_TIMESTAMP_FETCH_FAILED",
      error: `Failed to fetch login timestamp challenge: ${error.message}`,
    };
  }
}

/**
 * Login validation failures have a special contract:
 * - Silent mode: return no response body at all
 * - Non-silent mode: keep legacy flat error payload shape
 */
function respondLoginValidationFailure(res, { silenceLoginFailures, statusCode = 400, code, message, requestId }) {
  if (silenceLoginFailures) {
    return;
  }
  return sendError(res, {
    statusCode,
    requestId,
    code,
    message
  });
}

async function login_client(req, res) {
  const requestId = ulid();
  const startTime = Date.now();
  
  // Create a base context for this function
  const baseContext = createLogContext(
    "RoditAuth",
    "login_client",
    {
      requestId,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    }
  );

  logger.infoWithContext("Client login request received", baseContext); // Function call log
  // Determines whether login failures should be silent, configurable via SECURITY_OPTIONS.SILENT_LOGIN_FAILURES
  let silenceLoginFailures = false;

  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    silenceLoginFailures = config.get('SECURITY_OPTIONS.SILENT_LOGIN_FAILURES');

    if (loginBodyHasDeprecatedKeys(body)) {
      const duration = Date.now() - startTime;
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: "failure",
        reason: "deprecated_login_payload",
        error: "LOGIN_PAYLOAD_DEPRECATED",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: "failure",
        reason: "LOGIN_PAYLOAD_DEPRECATED",
      });
      return respondLoginValidationFailure(res, {
        silenceLoginFailures,
        statusCode: 400,
        requestId,
        code: "LOGIN_PAYLOAD_DEPRECATED",
        message:
          "Remove signature and account_id. Send roditid and accountid (one empty), timestamp, and base64url_signature (or roditid_base64url_signature for the same value - not both).",
      });
    }

    if (loginBodyHasDuplicateSignatureFields(body)) {
      const duration = Date.now() - startTime;
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: "failure",
        reason: "duplicate_signature_fields",
        error: "LOGIN_PAYLOAD_DEPRECATED",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: "failure",
        reason: "LOGIN_PAYLOAD_DEPRECATED",
      });
      return respondLoginValidationFailure(res, {
        silenceLoginFailures,
        statusCode: 400,
        requestId,
        code: "LOGIN_PAYLOAD_DEPRECATED",
        message:
          "Send exactly one signature field: base64url_signature or roditid_base64url_signature (same bytes), not both non-empty.",
      });
    }

    const roditid = normalizeOptionalLoginString(body.roditid);
    const accountid = normalizeOptionalLoginString(body.accountid);
    const hasRoditId = roditid.length > 0;
    const hasAccountId = accountid.length > 0;
    const peer_timestamp = parseRequiredLoginTimestamp(body.timestamp);
    const base64url_signature = extractLoginBase64UrlSignature(body);

    logger.infoWithContext("Login request identifiers (sanitized)", {
      ...baseContext,
      roditid: roditid || undefined,
      accountid: accountid || undefined,
      login_mode: hasRoditId ? "roditid" : hasAccountId ? "accountid" : "none",
      timestamp: peer_timestamp,
      has_base64url_signature: base64url_signature.length > 0,
    });

    if (hasRoditId && hasAccountId) {
      const duration = Date.now() - startTime;
      logger.debugWithContext("Ambiguous login identifiers (both roditid and accountid non-empty)", {
        ...baseContext,
        duration,
        result: "failure",
        reason: "login_identifier_ambiguous",
        bodyKeys: Object.keys(body),
      });
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: "failure",
        reason: "login_identifier_ambiguous",
        error: "LOGIN_IDENTIFIER_AMBIGUOUS",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: "failure",
        reason: "LOGIN_IDENTIFIER_AMBIGUOUS",
      });
      return respondLoginValidationFailure(res, {
        silenceLoginFailures,
        statusCode: 400,
        requestId,
        code: "LOGIN_IDENTIFIER_AMBIGUOUS",
        message:
          "Send exactly one of roditid or accountid non-empty; the other must be empty. Signature verifies against that single identifier.",
      });
    }

    if (!hasRoditId && !hasAccountId) {
      const duration = Date.now() - startTime;

      logger.debugWithContext("Missing login identifier in login request", {
        ...baseContext,
        duration,
        result: "failure",
        reason: "missing_login_identifier",
        bodyKeys: Object.keys(body),
      });
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: "failure",
        reason: "missing_login_identifier",
        error: "MISSING_LOGIN_IDENTIFIER",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: "failure",
        reason: "MISSING_LOGIN_IDENTIFIER",
      });

      return respondLoginValidationFailure(res, {
        silenceLoginFailures,
        statusCode: 400,
        requestId,
        code: "MISSING_LOGIN_IDENTIFIER",
        message:
          "Provide roditid (token id) or accountid (64-character hex NEAR implicit account); include both keys with exactly one non-empty value.",
      });
    }

    if (peer_timestamp === null) {
      const duration = Date.now() - startTime;

      logger.debugWithContext("Missing or invalid timestamp in login request", {
        ...baseContext,
        duration,
        result: "failure",
        reason: "invalid_login_timestamp",
        providedTimestampType: typeof body.timestamp,
      });
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: "failure",
        reason: "invalid_login_timestamp",
        error: "INVALID_LOGIN_TIMESTAMP",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: "failure",
        reason: "INVALID_LOGIN_TIMESTAMP",
      });

      return respondLoginValidationFailure(res, {
        silenceLoginFailures,
        statusCode: 400,
        requestId,
        code: "INVALID_LOGIN_TIMESTAMP",
        message:
          "Provide a valid Unix-seconds `timestamp` for POST /api/login (from the same GET /api/login/timestamp login challenge as your signature). The login signing payload is UTF-8 identifier + canonical timestamp_iso from that response.",
      });
    }

    const peer_roditid = hasRoditId ? roditid : accountid;

    if (!base64url_signature) {
      const duration = Date.now() - startTime;

      logger.debugWithContext("Missing base64url_signature in login request", {
        ...baseContext,
        duration,
        result: "failure",
        reason: "missing_base64url_signature",
        bodyKeys: Object.keys(body),
      });
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: "failure",
        reason: "missing_base64url_signature",
        error: "MISSING_BASE64URL_SIGNATURE",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: "failure",
        reason: "MISSING_BASE64URL_SIGNATURE",
      });

      return respondLoginValidationFailure(res, {
        silenceLoginFailures,
        statusCode: 400,
        requestId,
        code: "MISSING_BASE64URL_SIGNATURE",
        message:
          "Provide base64url_signature (or roditid_base64url_signature): base64url-encoded Ed25519 signature over the login signing payload — UTF-8 concatenation of your roditid or accountid with the canonical timestamp_iso from GET /api/login/timestamp (same login challenge as the Unix timestamp you send).",
      });
    }

    logger.debugWithContext("Login parameters extracted", {
      ...baseContext,
      hasRoditId: roditid.length > 0,
      hasAccountId: accountid.length > 0,
      hasTimestamp: peer_timestamp !== undefined && peer_timestamp !== null,
      has_base64url_signature: base64url_signature.length > 0,
    });

    logger.debugWithContext("Retrieving server configuration", baseContext);

    // Import stateManager only when needed to avoid circular dependencies
    const stateManager = require("../blockchain/statemanager");
    const config_own_rodit = await stateManager.getConfigOwnRodit();

    if (!config_own_rodit) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Server configuration not initialized",
        {
          ...baseContext,
          duration,
          errorCode: "CONFIG_NOT_INITIALIZED"
        },
        new Error("Server configuration not initialized"),
        "login_error",
        { error_type: "config_error" }
      );

      // Emit metrics for dashboards
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        error: "CONFIG_NOT_INITIALIZED",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        reason: "CONFIG_NOT_INITIALIZED",
      });

      throw new Error("Error 0112: Server configuration not initialized");
    }

    logger.debugWithContext("Verifying peer RODiT credentials", {
      ...baseContext,
      hasRoditId,
      hasAccountId,
      peerRoditIdForVerify: peer_roditid,
      signature_covers: hasRoditId ? "roditid" : "accountid",
    });

    logger.debugWithContext("Resolving and verifying peer RODiT", {
      ...baseContext,
      peerRoditId: peer_roditid,
    });
    const result = await verify_peer_rodit(
      await resolve_peer_rodit_for_login(roditid, accountid),
      peer_roditid,
      peer_timestamp,
      base64url_signature
    );

    const { peer_rodit, goodrodit: isRoditValid, failureReason, failureMessage } = result;

    if (!isRoditValid) {
      const duration = Date.now() - startTime;

      logger.debugWithContext("Invalid RODiT credentials", {
        ...baseContext,
        duration,
        result: 'failure',
        reason: failureReason || 'Invalid credentials',
        failureMessage: failureMessage || 'Unknown failure',
        roditId: peer_roditid
      });
      // Emit metrics for dashboards
      logger.metric("login_attempt_duration_ms", duration, {
        component: "RoditAuth",
        success: false,
        result: 'failure',
        reason: failureReason || 'Invalid credentials',
        error: failureReason || "INVALID_CREDENTIALS",
      });
      logger.metric("failed_login_attempts_total", 1, {
        component: "RoditAuth",
        result: 'failure',
        reason: failureReason || "Invalid credentials",
      });

      if (!silenceLoginFailures) {
        return sendError(res, {
          statusCode: 401,
          requestId,
          code: failureReason || "INVALID_CREDENTIALS",
          message: `Error 102: Login attempt failed: ${failureMessage || 'Invalid RODiT or Signature'}`,
          details: {
            failureReason: failureReason || null,
            failureMessage: failureMessage || null
          }
        });
      }
      // Completely silent - no response at all
      return;
    }

    const jwt_token = await generate_jwt_token(
      peer_rodit,
      peer_timestamp,
      config_own_rodit.own_rodit,
      config_own_rodit.own_rodit_bytes_private_key
    );

    const duration = Date.now() - startTime;
    logger.infoWithContext("Issued login JWT token", {
      ...baseContext,
      decision: "issued",
      reason: "login_client authentication succeeded",
      jwtTokenLength: jwt_token?.length
    });
    logger.infoWithContext("Login successful", {
      ...baseContext,
      duration,
      result: 'success',
      reason: 'Authenticated successfully',
      roditId: peer_rodit.token_id
    });
    // Emit metrics for dashboards
    logger.metric("login_attempt_duration_ms", duration, {
      component: "RoditAuth",
      success: true,
      result: 'success',
      reason: 'Authenticated successfully'
    });
    logger.metric("successful_logins_total", 1, {
      component: "RoditAuth",
      result: 'success',
      reason: 'Authenticated successfully'
    });

    // Set the jwt_token in the response header
    res.setHeader('New-Token', jwt_token);

    return res.json({
      jwt_token,
      requestId
    });
  } catch (error) {
    const duration = Date.now() - startTime;

    logErrorWithMetrics(
      "Login authentication failed",
      {
        ...baseContext,
        duration,
        result: 'failure',
        reason: error.message || error.code || 'Unknown error',
        errorCode: error.code || "UNKNOWN_ERROR"
      },
      error,
      "login_error",
      { error_type: "authentication_error" }
    );
    // Emit metrics for dashboards
    logger.metric("login_attempt_duration_ms", duration, {
      component: "RoditAuth",
      success: false,
      result: 'failure',
      reason: error.message || error.code || 'Unknown error',
      error: error.code || "UNKNOWN_ERROR",
    });
    logger.metric("failed_login_attempts_total", 1, {
      component: "RoditAuth",
      result: 'failure',
      reason: error.message || error.code || 'Unknown error',
    });

    if (!silenceLoginFailures) {
      return sendError(res, {
        statusCode: 401,
        requestId,
        code: "LOGIN_ERROR",
        message: `Error 105: Login attempt failed: ${error.message}`
      });
    }
    // Completely silent - no response at all
    return;
  }
}


  /**
   * Extract jwt_token from authorization header
   *
   * @param {string} authHeader - Authorization header
   * @returns {string|null} Extracted jwt_token or null
   */
  function extractTokenFromHeader(authHeader) {
    const startTime = Date.now();
    const requestId = ulid();
    
    // Create a base context for this function
    const baseContext = createLogContext(
      "TokenExtractor",
      "extractTokenFromHeader",
      { requestId }
    );

    if (!authHeader) {
      logger.debugWithContext("No authorization header present", baseContext);
      return null;
    }

    const [bearer, jwt_token] = authHeader.split(" ");

    if (bearer.toLowerCase() !== "bearer" || !jwt_token) {
      logger.debugWithContext("Invalid authorization header format", {
        ...baseContext,
        headerFormat: authHeader ? authHeader.substring(0, 50) + '...' : 'null',
        bearerPart: bearer,
        hasToken: !!jwt_token
      });
      return null;
    }

    return jwt_token;
  }

  /**
   * Middleware to authenticate API calls
   *
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  async function authenticate_apicall(req, res, next) {
    const startTime = Date.now();
    const requestId = ulid();
    
    // Debug: Log incoming request details
    logger.debugWithContext("Authentication middleware called", {
      component: "AuthMiddleware",
      method: "authenticate_apicall", 
      requestId,
      path: req.path,
      httpMethod: req.method,
      hasAuthHeader: !!req.headers.authorization,
      allHeaders: Object.keys(req.headers)
    });
    
    const jwt_token = extractTokenFromHeader(req.headers.authorization);
    
    // Create a base context for this function
    const baseContext = createLogContext(
      "AuthMiddleware",
      "authenticate_apicall",
      {
        requestId,
        path: req.path,
        method: req.method
      }
    );

    logger.infoWithContext("API authentication started", {
      ...baseContext,
      hasToken: !!jwt_token,
      result: 'call',
      reason: 'API authentication started'
    }); // Function call log

    try {
      // Verify sessionManager is properly initialized before using it
      verifySessionManager();
      
      if (!jwt_token) {
        // Add metric for missing jwt_token
        logger.metric('auth_operations', Date.now() - startTime, {
          operation: 'authenticate_apicall',
          result: 'failure',
          reason: 'No jwt_token provided'
        });
        return sendError(res, {
          statusCode: 401,
          requestId,
          code: "MISSING_TOKEN",
          message: "No jwt_token provided"
        });
      }
      
      // Check if token is valid by checking session state
      const isTokenInvalid = await sessionManager.isTokenInvalidated(jwt_token);
      
      if (isTokenInvalid) {
        const invalidationInfo = await sessionManager.getTokenInvalidationInfo(jwt_token);
        
        // Add metric for invalid token
        logger.metric('auth_operations', Date.now() - startTime, {
          operation: 'authenticate_apicall',
          result: 'failure',
          reason: invalidationInfo?.reason || 'Session not active'
        });
        
        return sendError(res, {
          statusCode: 401,
          requestId,
          code: "INVALIDATED_TOKEN",
          message: "Token has been invalidated",
          details: {
            reason: invalidationInfo?.reason || "session_inactive",
            invalidatedAt: invalidationInfo?.timestamp
          }
        });
      }

      // Get own RODiT configuration first
      const config_own_rodit = await stateManager.getConfigOwnRodit();

      if (!config_own_rodit || !config_own_rodit.own_rodit) {
        logErrorWithMetrics(
          "Server configuration not initialized",
          {
            ...baseContext,
            hasConfig: !!config_own_rodit
          },
          new Error("Server configuration not initialized"),
          "auth_error",
          { error_type: "config_error" }
        );
        return sendError(res, {
          statusCode: 500,
          requestId,
          code: "SERVER_CONFIG_ERROR",
          message: "Server configuration not initialized"
        });
      }

      // Use the jwt_token service to validate the jwt_token WITH the own_rodit parameter
      let validationResult;
      try {
        // Decode opportunistically so malformed tokens fail fast before full validation.
        try {
          const { decodeJwt } = await getJose();
          decodeJwt(jwt_token);
        } catch (_decodeError) {}
        
        validationResult = await validate_jwt_token_be(
          jwt_token,
          config_own_rodit.own_rodit
        );
      } catch (validationError) {
        // Handle specific validation errors
        // Add metric for jwt_token validation failure
        logger.metric('auth_operations', Date.now() - startTime, {
          operation: 'authenticate_apicall',
          result: 'failure',
          reason: validationError.message || 'Token validation failed'
        });
        return sendError(res, {
          statusCode: 403,
          requestId,
          code: validationError.code || "INVALID_TOKEN",
          message: validationError.message || "Invalid jwt_token"
        });
      }

      if (!validationResult.valid) {
        // Add metric for invalid jwt_token
        logger.metric('auth_operations', Date.now() - startTime, {
          operation: 'authenticate_apicall',
          result: 'failure',
          reason: validationResult.error || 'Invalid jwt_token'
        });
        // Return 403 for invalid jwt_tokens
        return sendError(res, {
          statusCode: 403,
          requestId,
          code: validationResult.errorCode || "INVALID_TOKEN",
          message: "Invalid jwt_token",
          details: validationResult.error ? { error: validationResult.error } : undefined
        });
      }

      // IMPORTANT: Attach the raw payload to req.user to maintain exact compatibility
      // with digital signature verification processes
      req.user = validationResult.payload;
      
      // Store the jwt_token for potential use in the request
      req.jwt_token = jwt_token;

      // Check if a new jwt_token was generated during validation
      if (validationResult.newToken) {
        // Add the new jwt_token to the response headers ONLY (no cookies)
        res.setHeader('New-Token', validationResult.newToken);
      }

      const duration = Date.now() - startTime;
      logger.infoWithContext("Authentication successful", {
        ...baseContext,
        userId: req.user.sub, // Use sub from raw payload
        duration,
        decision: "accepted",
        result: 'success',
        reason: 'Authentication successful'
      });
      // Add metric for successful authentication
      logger.metric('auth_operations', duration, {
        operation: 'authenticate_apicall',
        result: 'success',
        reason: 'Authentication successful'
      });

      next();
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.debugWithContext("Authentication rejected by exception", {
        ...baseContext,
        decision: "rejected",
        reason: error.message || "Authentication failed",
        errorName: error.name,
        errorCode: error.code
      });
      logErrorWithMetrics(
        "Authentication error",
        {
          ...baseContext,
          duration,
          result: 'failure',
          reason: error.message || 'Authentication failed'
        },
        error,
        "auth_error",
        { error_type: "authentication_error" }
      );
      // Add metric for authentication error
      logger.metric('auth_operations', duration, {
        operation: 'authenticate_apicall',
        result: 'failure',
        reason: error.message || 'Authentication failed'
      });

      return sendError(res, {
        statusCode: 500,
        requestId,
        code: "AUTH_ERROR",
        message: "Authentication failed",
        details: !isStrictEnvironment() ? { cause: error.message } : undefined
      });
    }
  }

  /**
   * Middleware to authenticate logout calls.
   * Allows signature-valid expired tokens so sessions can be closed cleanly.
   *
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  async function authenticate_logout(req, res, next) {
    const requestId = ulid();
    const startTime = Date.now();
    const baseContext = createLogContext(
      "AuthMiddleware",
      "authenticate_logout",
      {
        requestId,
        path: req.path,
        method: req.method
      }
    );

    try {
      verifySessionManager();
      const jwt_token = extractTokenFromHeader(req.headers.authorization);
      if (!jwt_token) {
        return sendError(res, {
          statusCode: 401,
          requestId,
          code: "MISSING_TOKEN",
          message: "No jwt_token provided"
        });
      }

      const config_own_rodit = await stateManager.getConfigOwnRodit();
      if (!config_own_rodit || !config_own_rodit.own_rodit) {
        return sendError(res, {
          statusCode: 500,
          requestId,
          code: "SERVER_CONFIG_ERROR",
          message: "Server configuration not initialized"
        });
      }

      // Logout-specific auth: signature and claims must be valid, expiration is tolerated.
      const validationResult = await validate_jwt_token_be(
        jwt_token,
        config_own_rodit.own_rodit,
        { allowExpiredToken: true }
      );

      if (!validationResult.valid) {
        return sendError(res, {
          statusCode: 403,
          requestId,
          code: validationResult.errorCode || "INVALID_TOKEN",
          message: validationResult.error || "Invalid jwt_token"
        });
      }

      req.user = validationResult.payload;
      req.jwt_token = jwt_token;

      logger.infoWithContext("Logout authentication successful", {
        ...baseContext,
        duration: Date.now() - startTime,
        userId: req.user?.sub
      });
      return next();
    } catch (error) {
      logger.debugWithContext("Logout authentication failed", {
        ...baseContext,
        duration: Date.now() - startTime,
        error: error.message
      });
      return sendError(res, {
        statusCode: 403,
        requestId,
        code: error.code || "INVALID_TOKEN",
        message: error.message || "Invalid jwt_token"
      });
    }
  }

  /**
   * Handle client logout
   *
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} Response object
   */
  async function logout_client(req, res) {
    const requestId = ulid();
    const startTime = Date.now();
    
    // Create a base context for this function
    const baseContext = createLogContext(
      "AuthenticationService",
      "logout_client",
      {
        requestId,
        path: req.path,
        method: req.method,
        ip: req.ip
      }
    );

    logger.infoWithContext("Logout request received", {
      ...baseContext,
      userAgent: req.get("User-Agent")
    });

    try {
      // Verify sessionManager is properly initialized before using it
      verifySessionManager();
      
      // Extract jwt_token from authorization header
      const jwt_token =
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer ")
          ? req.headers.authorization.substring(7)
          : null;

      if (!jwt_token) {
        const duration = Date.now() - startTime;

        // Emit metrics for unauthorized logout attempts
        logger.metric &&
          logger.metric("logout_attempts", 1, {
            component: "AuthenticationService",
            result: "no_jwt_token",
          });

        return sendError(res, {
          statusCode: 401,
          requestId,
          code: "MISSING_TOKEN",
          message: "No authentication jwt_token provided"
        });
      }

      // Decode the jwt_token to get session information
      // We're just decoding, not verifying, since even if the jwt_token is expired
      // we still want to be able to log the user out
      let decodedToken;
      try {
        // Split the jwt_token and decode the payload (middle part)
        const parts = jwt_token.split(".");
        if (parts.length !== 3) {
          throw new Error("Invalid jwt_token format");
        }

        const payload = Buffer.from(parts[1], "base64url").toString();
        decodedToken = JSON.parse(payload);
      } catch (decodeError) {
        logErrorWithMetrics(
          "Failed to decode jwt_token for logout",
          {
            ...baseContext,
            jwt_tokenLength: jwt_token?.length
          },
          decodeError,
          "logout_error",
          { error_type: "jwt_token_decode_error" }
        );

        // Continue with a partial logout even if jwt_token can't be decoded
        decodedToken = {};
      }

      // Track success for metrics
      let logoutSuccess = false;
      let sessionClosed = false;
      let sessionStatus = "unknown";
      let jwt_tokenInvalidated = null;
      let finalToken = null;

      // Close the session if session_id is available
      if (decodedToken.session_id) {
        try {
          // Get the reason from request body or use default
          const reason = (req.body && req.body.reason) || "user_logout";

          // Invalidate the jwt_token by closing its session
          jwt_tokenInvalidated = await sessionManager.invalidateToken(jwt_token, reason, decodedToken.session_id);
          
          logger.infoWithContext("Token invalidation result (session-based)", {
            ...baseContext,
            jwt_tokenInvalidated,
            jwt_tokenLength: jwt_token.length,
            reason,
            sessionId: decodedToken.session_id,
            method: "session_closure"
          });
          
          // Verify the token was actually invalidated by checking session state
          const verifyInvalidation = await sessionManager.isTokenInvalidated(jwt_token);
          const invalidationInfo = await sessionManager.getTokenInvalidationInfo(jwt_token);
          
          logger.infoWithContext("Token invalidation verification (session-based)", {
            ...baseContext,
            verifyInvalidation,
            expectedInvalidated: true,
            invalidationWorking: verifyInvalidation === true,
            sessionId: decodedToken.session_id,
            invalidationInfo: invalidationInfo ? {
              reason: invalidationInfo.reason,
              invalidatedAt: invalidationInfo.invalidatedAt,
              sessionId: invalidationInfo.sessionId
            } : null
          });
          
          // Critical security check - log if invalidation failed
          if (!verifyInvalidation) {
            logger.errorWithContext("CRITICAL: Token invalidation failed - security risk!", {
              ...baseContext,
              jwt_tokenInvalidated,
              verifyInvalidation,
              securityIssue: true
            });
          } else {
            logger.infoWithContext("SECURITY: Token successfully invalidated", {
              ...baseContext,
              securityConfirmed: true
            });
          }

          // Then close the session
          sessionClosed = await sessionManager.closeSession(
            decodedToken.session_id,
            reason,
            null // Don't pass jwt_token here since we've already invalidated it
          );
          
          logger.infoWithContext("Session closure result", {
            ...baseContext,
            sessionClosed
          });
          
          // Update tracking variables for metrics and response
          // Primary requirement: JWT token must be invalidated for security
          // Secondary requirement: Session closure (but not critical if session was already cleaned up)
          logoutSuccess = jwt_tokenInvalidated; // Token invalidation is the critical security requirement
          
          logger.infoWithContext("Logout success calculation", {
            ...baseContext,
            jwt_tokenInvalidated,
            sessionClosed,
            logoutSuccess,
            primaryRequirement: "jwt_token_invalidated",
            secondaryRequirement: "session_closed",
            securitySatisfied: jwt_tokenInvalidated
          });
          
          // Determine the overall session status
          if (jwt_tokenInvalidated && sessionClosed) {
            sessionStatus = "closed_complete";
          } else if (jwt_tokenInvalidated) {
            sessionStatus = "closed_jwt_token_only";
          } else if (sessionClosed) {
            sessionStatus = "closed_session_only";
          } else {
            sessionStatus = "close_failed";
          }
          
          // Generate a final jwt_token with session_status="closed"
          try {
            // Import the tokenservice dynamically to avoid circular dependencies
            const jwt_tokenService = require('../auth/tokenservice');
            
            // Generate a final jwt_token with very short expiration (1 minute)
            // This jwt_token is just for status communication, not for authentication
            finalToken = await jwt_tokenService.generate_session_termination_token(
              decodedToken,
              60 // 1 minute duration
            );
            
            logger.infoWithContext("Generated final jwt_token with closed status", {
              ...baseContext,
              hasToken: !!finalToken
            });
          } catch (jwt_tokenError) {
            logErrorWithMetrics(
              "Failed to generate final jwt_token",
              baseContext,
              jwt_tokenError,
              "logout_error",
              { error_type: "jwt_token_generation_error" }
            );
          }
        } catch (sessionError) {
          logErrorWithMetrics(
            "Error closing session",
            {
              ...baseContext,
              sessionId: decodedToken.session_id
            },
            sessionError,
            "logout_error",
            { error_type: "session_closure_error" }
          );

          // Continue with logout process even if session closing fails
        }
      } else {
        // We still consider this a success since there's no session to log out from
        logoutSuccess = true;
      }

      // Clear auth headers if they exist
      if (typeof res.removeHeader === 'function') {
        res.removeHeader("Authorization");
      }
      
      // Set the final jwt_token in the response header if available
      if (finalToken) {
        res.set("New-Token", finalToken);
      }

      const duration = Date.now() - startTime;
      logger.infoWithContext("Logout completed", {
        ...baseContext,
        duration,
        success: logoutSuccess,
        sessionClosed,
        hasSessionId: !!decodedToken.session_id
      });

      // Emit metrics for logout
      logger.metric &&
        logger.metric("logout_duration_ms", duration, {
          component: "AuthenticationService",
          success: logoutSuccess,
          session_closed: sessionClosed,
          session_status: sessionStatus
        });

      logger.metric &&
        logger.metric("logout_attempts", 1, {
          component: "AuthenticationService",
          result: logoutSuccess ? "success" : "failure",
          session_closed: sessionClosed,
          session_status: sessionStatus
        });

      return res.json({
        message: "Logout successful",
        sessionClosed,
        sessionStatus,
        jwt_tokenInvalidated,
        requestId,
      });
    } catch (error) {
      const duration = Date.now() - startTime;

      logErrorWithMetrics(
        "Logout process failed",
        {
          ...baseContext,
          duration
        },
        error,
        "logout_error",
        { error_type: "general_logout_error" }
      );

      // Emit metrics for logout errors
      logger.metric &&
        logger.metric("logout_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: error.constructor.name,
        });

      logger.metric &&
        logger.metric("logout_errors", 1, {
          component: "AuthenticationService",
          error: error.constructor.name,
        });

      return sendError(res, {
        statusCode: 500,
        requestId,
        code: "LOGOUT_ERROR",
        message: "Internal server error during logout",
        details: !isStrictEnvironment() ? { error: error.message } : undefined
      });
    }
  }

  /**
   * Handle client login with NEP-413 standard
   *
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Object} config_own_rodit - Own RODiT configuration
   * @returns {Object} Response with JWT jwt_token or error
   */
 async function login_client_withnep413(req, res, config_own_rodit = null) {
    const requestId = ulid();
    const startTime = Date.now();

    logger.info("NEP-413 login request received", {
      component: "AuthenticationService",
      method: "login_client_withnep413",
      requestId,
    });

    try {
      const { signature, message, nonce, recipient, callbackUrl } = req.body;

      logger.debug("Received NEP-413 login parameters", {
        component: "AuthenticationService",
        method: "login_client_withnep413",
        requestId,
        message,
        recipient,
        hasSignature: !!signature,
        hasNonce: !!nonce,
        hasCallbackUrl: !!callbackUrl,
      });

      if (!config_own_rodit) {
        const duration = Date.now() - startTime;

        logger.error("Server configuration not initialized for NEP-413 login", {
          component: "AuthenticationService",
          method: "login_client_withnep413",
          requestId,
          duration,
          errorCode: "CONFIG_NOT_INITIALIZED",
        });

        // Emit metrics for dashboards
        logger.metric("nep413_login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: "CONFIG_NOT_INITIALIZED",
        });
        logger.metric("failed_nep413_logins_total", 1, {
          component: "AuthenticationService",
          reason: "CONFIG_NOT_INITIALIZED",
        });

        throw new Error("Error 0114: Server configuration not initialized");
      }

      logger.debug("Verifying NEP-413 RODiT credentials", {
        component: "AuthenticationService",
        method: "login_client_withnep413",
        requestId,
      });

      // Declare peer_rodit outside the try block so it's accessible throughout the function
      let peer_rodit;
      
      try {
        // First, fetch the peer RODiT using message (which contains the RODiT)
        peer_rodit = await nearorg_rpc_tokenfromroditid(message);
        
        if (!peer_rodit || !peer_rodit.token_id) {
          logger.error("Failed to retrieve peer RODiT data", {
            component: "AuthenticationService",
            method: "login_client_withnep413",
            requestId,
            message
          });
          throw new Error("Error 0115: Invalid RODiT");
        }
        
        // Now verify the signature using NEP-413 parameters
        const isRoditValid = await verify_rodit_ownership_withnep413(
          message,
          nonce,
          recipient,
          callbackUrl,
          signature,
          peer_rodit
        );

        if (!isRoditValid) {
          const duration = Date.now() - startTime;

          logger.warn("NEP-413 login failed - Invalid RODiT credentials", {
            component: "AuthenticationService",
            method: "login_client_withnep413",
            requestId,
            duration,
            message,
          });

          // Emit metrics for dashboards
          logger.metric("nep413_login_duration_ms", duration, {
            component: "AuthenticationService",
            success: false,
            error: "INVALID_CREDENTIALS",
          });
          logger.metric("failed_nep413_logins_total", 1, {
            component: "AuthenticationService",
            reason: "INVALID_CREDENTIALS",
          });

          return sendError(res, {
            statusCode: 401,
            requestId,
            code: "INVALID_CREDENTIALS",
            message:
              "Error 106: Login attempt failed: Invalid RODiT or Signature"
          });
        }

      } catch (innerError) {
        const duration = Date.now() - startTime;
        logger.error(`NEP-413 verification error: ${innerError.message}`, {
          component: "AuthenticationService",
          method: "login_client_withnep413",
          requestId,
          duration,
          error: innerError.message,
        });
        
        return sendError(res, {
          statusCode: 401,
          requestId,
          code: "LOGIN_VERIFICATION_FAILED",
          message: `Error 107: Login verification failed: ${innerError.message}`
        });
      }
      
      const jwt_token = await generate_jwt_token(
        peer_rodit,
        Math.floor(Date.now() / 1000),
        config_own_rodit.own_rodit,
        config_own_rodit.own_rodit_bytes_private_key
      );

      const duration = Date.now() - startTime;
      logger.info("NEP-413 login successful", {
        component: "AuthenticationService",
        method: "login_client_withnep413",
        requestId,
        duration,
        roditId: peer_rodit.token_id,
      });

      // Emit metrics for dashboards
      logger.metric("nep413_login_duration_ms", duration, {
        component: "AuthenticationService",
        success: true,
      });
      logger.metric("successful_nep413_logins_total", 1, {
        component: "AuthenticationService",
      });

      // Log the response being sent to frontend
      logger.info("Sending NEP-413 login response to frontend", {
        component: "AuthenticationService",
        method: "login_client_withnep413",
        requestId,
        response: {
          requestId: requestId,
          jwt_token_length: jwt_token ? jwt_token.length : 0
        }
      });

      return res.json({
        jwt_token,
        requestId,
      });
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error("NEP-413 login failed", {
        component: "AuthenticationService",
        method: "login_client_withnep413",
        requestId,
        duration,
        errorMessage: error.message,
        errorCode: error.code || "UNKNOWN_ERROR",
        stack: error.stack,
      });

      // Emit metrics for dashboards
      logger.metric("nep413_login_duration_ms", duration, {
        component: "AuthenticationService",
        success: false,
        error: error.code || "UNKNOWN_ERROR",
      });
      logger.metric("failed_nep413_logins_total", 1, {
        component: "AuthenticationService",
        reason: error.code || "UNKNOWN_ERROR",
      });

      return sendError(res, {
        statusCode: 500,
        requestId,
        code: error.code || "NEP413_LOGIN_ERROR",
        message: `Error 175c: Login attempt failed: ${error.message}`
      });
    }
  }

  /**
   * Login the server to a RODiT portal
   *
   * @param {Object} config_own_rodit - Configuration object containing own_rodit and other settings
 * @param {number} port - Optional port number for the portal URL
 * @param {Object} [options] - Optional settings
 * @param {number} [options.timestamp] - Unix seconds used for signature generation (if omitted, local current time is used)
 * @param {string} [options.accountId] - Explicit NEAR account for outbound login when token id absent
 * @param {string} [options.loginPath] - HTTP path (default /api/login)
   * @returns {Promise<Object>} Login result
   */
async function login_portal(config_own_rodit, port, options = {}) {
  const requestId = ulid();
  const startTime = Date.now();
  
  // Access the own_rodit object from the config
  const own_rodit = config_own_rodit.own_rodit;

  logger.info("Starting portal login process", {
    component: "AuthenticationService",
    method: "login_portal",
    requestId,
    roditId: own_rodit?.token_id,
  });

  try {
      logger.debug("Using provided configuration", {
        component: "AuthenticationService",
        method: "login_portal",
        requestId,
        hasConfig: !!config_own_rodit,
        api_ep: config_own_rodit?.apiendpoint,
      });

      if (!config_own_rodit) {
        const duration = Date.now() - startTime;

        logger.error("Client configuration not initialized", {
          component: "AuthenticationService",
          method: "login_portal",
          requestId,
          duration,
          errorCode: "CONFIG_NOT_INITIALIZED",
        });

        // Emit metrics for dashboards
        logger.metric("portal_login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: "CONFIG_NOT_INITIALIZED",
        });
        logger.metric("portal_login_errors_total", 1, {
          component: "AuthenticationService",
          error: "CONFIG_NOT_INITIALIZED",
        });

        return {
          error: "Client configuration not initialized",
          requestId,
        };
      }

      // Check RODiT metadata
      if (!own_rodit.metadata || !own_rodit.metadata.serviceprovider_id) {
        const duration = Date.now() - startTime;

        logger.error("Missing serviceprovider_id in RODiT", {
          component: "AuthenticationService",
          method: "login_portal",
          requestId,
          duration,
          roditId: own_rodit?.token_id,
          hasMetadata: !!own_rodit?.metadata,
        });

        // Emit metrics for dashboards
        logger.metric("portal_login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: "MISSING_METADATA",
        });
        logger.metric("portal_login_errors_total", 1, {
          component: "AuthenticationService",
          error: "MISSING_METADATA",
        });

        return {
          error: "Missing serviceprovider_id in RODiT",
          requestId,
        };
      }

      // Use stateManager's getPortalUrl method to get API endpoint
      const serviceProviderId = own_rodit.metadata.serviceprovider_id;
      const apiendpoint = stateManager.getPortalUrl(
        serviceProviderId,
        port
      );

      logger.info("Using portal endpoint", {
        component: "AuthenticationService",
        method: "login_portal",
        requestId,
        api_ep: apiendpoint,
      });

      // Prepare authentication data using the same payload contract as login_client.
      const roditid = normalizeOptionalLoginString(own_rodit?.token_id);
      const accountid = normalizeOptionalServerAccountId(options.accountId);
      const timestamp = parseRequiredServerLoginTimestamp(options.timestamp)
        ?? Math.floor(Date.now() / 1000);
      if (timestamp === null) {
        return {
          error: "Missing or invalid options.timestamp",
          errorCode: "INVALID_LOGIN_TIMESTAMP",
          failureReason: "INVALID_LOGIN_TIMESTAMP",
          requestId
        };
      }

      const hasRoditId = roditid.length > 0;
      const hasAccountId = accountid.length > 0;
      if (hasRoditId === hasAccountId) {
        return {
          error: "Provide exactly one signing identifier: own_rodit.token_id or options.accountId",
          errorCode: "LOGIN_IDENTIFIER_AMBIGUOUS",
          failureReason: "LOGIN_IDENTIFIER_AMBIGUOUS",
          requestId
        };
      }

      const timeString = await unixTimeToDateString(timestamp);
      const signatureIdentifier = hasRoditId ? roditid : accountid;
      const signatureIdentifierandtimestamp = new TextEncoder().encode(
        signatureIdentifier + timeString
      );

      logger.debug("Generating authentication signature", {
        component: "AuthenticationService",
        method: "login_portal",
        requestId,
        roditId: roditid,
        accountId: accountid,
        timestamp,
      });

      // Create signature
      const own_rodit_bytes_signature = nacl.sign.detached(
        signatureIdentifierandtimestamp,
        config_own_rodit.own_rodit_bytes_private_key
      );
      const roditid_base64url_signature = Buffer.from(
        own_rodit_bytes_signature
      ).toString("base64url");

      const loginPath =
        options.loginPath ??
        config_own_rodit.login_rodit_path ??
        config.get("LOGIN_RODIT_PATH", "/api/login");
      const fetchUrl = buildLoginUrl(apiendpoint, loginPath);

      logger.debug("Sending login request to portal", {
        component: "AuthenticationService",
        method: "login_portal",
        requestId,
        apiEndpoint: fetchUrl,
      });

      try {
        const response = await fetch(fetchUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            ...(hasRoditId ? { roditid } : {}),
            ...(hasAccountId ? { accountid } : {}),
            timestamp,
            roditid_base64url_signature,
          }),
        });

        if (!response.ok) {
          const duration = Date.now() - startTime;

          // Enhanced error logging with clear cause and effect
          logger.error(`Portal login request failed: HTTP ${response.status} response from SignPortal`, {
            component: "AuthenticationService",
            method: "login_portal",
            requestId,
            duration,
            status: response.status,
            statusText: response.statusText,
            apiEndpoint: fetchUrl,
            reason: `SignPortal server returned error status ${response.status} (${response.statusText})`,
            impact: "Cannot obtain authentication jwt_token due to server-side error"
          });

          // Emit metrics for dashboards
          logger.metric("portal_login_duration_ms", duration, {
            component: "AuthenticationService",
            success: false,
            error: "HTTP_ERROR",
            status: response.status,
          });
          logger.metric("portal_login_errors_total", 1, {
            component: "AuthenticationService",
            error: "HTTP_ERROR",
            status: response.status,
          });

          throw new Error(
            `Error 040: Portal login failed with status ${response.status}`
          );
        }

        const data = await response.json();
        let jwt_token = data.jwt_token;

        // Validate JWT jwt_token
        try {
          // First, decode the JWT without verification to get the rodit_id
          const { decodeJwt } = await getJose();
          const unverifiedPayload = decodeJwt(jwt_token);
          const peerRoditId = unverifiedPayload.rodit_id;
          
          // Fetch the peer RODiT information directly from the blockchain
          const peer_rodit = await nearorg_rpc_tokenfromroditid(peerRoditId);
          
          logger.debug("Fetched peer RODiT for validation", {
            component: "AuthenticationService",
            method: "login_portal",
            requestId,
            peer_rodit: {
              token_id: peer_rodit?.token_id,
              owner_id: peer_rodit?.owner_id,
              metadata: {
                serviceprovider_id: peer_rodit?.metadata?.serviceprovider_id
              }
            }
          });
          
          // Now perform the full validation
          const validationResult = await validate_jwt_token_be(
            jwt_token,
            peer_rodit,
            RELAXED_SESSION_VALIDATION_OPTIONS
          );

        } catch (validationError) {
          const duration = Date.now() - startTime;

          // Enhanced error logging with clear cause and effect
          logger.error("JWT jwt_token validation failed: Token received from portal is invalid", {
            component: "AuthenticationService",
            method: "login_portal",
            requestId,
            duration,
            errorMessage: validationError.message,
            errorType: validationError.name,
            stack: validationError.stack,
            reason: `JWT validation error: ${validationError.message}`,
            impact: "Cannot use the received jwt_token for authentication"
          });

          // Emit metrics for dashboards
          logger.metric("portal_login_duration_ms", duration, {
            component: "AuthenticationService",
            success: false,
            error: "JWT_VALIDATION_FAILED",
          });
          logger.metric("portal_login_errors_total", 1, {
            component: "AuthenticationService",
            error: "JWT_VALIDATION_FAILED",
          });

          throw new Error(
            `Error 039: Portal server validation failed: ${validationError.message}`
          );
        }

        const duration = Date.now() - startTime;
        logger.info("Portal login successful", {
          component: "AuthenticationService",
          method: "login_portal",
          requestId,
          duration,
          api_ep: apiendpoint,
        });

        // Emit metrics for dashboards
        logger.metric("portal_login_duration_ms", duration, {
          component: "AuthenticationService",
          success: true,
        });
        logger.metric("successful_portal_logins_total", 1, {
          component: "AuthenticationService",
          apiEndpoint: apiendpoint,
        });

        return {
          jwt_token,
          apiendpoint,
          requestId,
        };
      } catch (fetchError) {
        const duration = Date.now() - startTime;

        // Enhanced error logging with clear cause and effect
        logger.error("Portal fetch operation failed: Unable to connect to SignPortal endpoint", {
          component: "AuthenticationService",
          method: "login_portal",
          requestId,
          duration,
          errorMessage: fetchError.message,
          errorType: fetchError.name,
          stack: fetchError.stack,
          apiEndpoint: fetchUrl,
          reason: "Network connectivity issue or service unavailable",
          impact: "Authentication process cannot proceed without portal connection"
        });

        // Emit metrics for dashboards
        logger.metric("portal_login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: "FETCH_FAILED",
        });
        logger.metric("portal_login_errors_total", 1, {
          component: "AuthenticationService",
          error: "FETCH_FAILED",
          apiEndpoint: fetchUrl,
        });

        throw fetchError;
      }
    } catch (error) {
      const duration = Date.now() - startTime;

      // Enhanced error logging with clear cause and effect
      const errorType = error.name || error.constructor.name;
      const errorReason = error.message || 'Unknown error';
      
      logger.error(`Portal login process failed: ${errorType}`, {
        component: "AuthenticationService",
        method: "login_portal",
        requestId,
        duration,
        errorMessage: error.message,
        errorType: errorType,
        stack: error.stack,
        roditId: own_rodit?.token_id,
        reason: errorReason,
        impact: "Unable to authenticate with SignPortal, client operations requiring authentication will fail"
      });

      // Emit metrics for dashboards
      logger.metric("portal_login_duration_ms", duration, {
        component: "AuthenticationService",
        success: false,
        error: error.constructor.name,
      });
      logger.metric("portal_login_errors_total", 1, {
        component: "AuthenticationService",
        error: error.constructor.name,
      });

      // Return structured error information
      return {
        error: `Failed to login to portal: ${error.message}`,
        reason: error.name || error.constructor.name,
        details: error.message,
        impact: "Authentication with SignPortal failed, client operations requiring authentication will fail",
        requestId,
      };
    }
  }

  /**
   * Login to a peer API (POST /api/login shape expected by the peer). Signs roditid+timestamp when
   * own_rodit.token_id is set; otherwise signs NEAR account id + timestamp when options/config supply an account.
   * Body uses roditid_base64url_signature (stable wire field name). Peer login_client accepts this field or base64url_signature (same bytes).
   *
   * @param {Object} config_own_rodit - Configuration object containing own_rodit and private key
   * @param {Object} [options] - Optional settings
   * @param {string} [options.loginPath] - HTTP path (default /api/login)
   * @param {number} [options.timestamp] - Unix seconds used for signature generation (if omitted, fetched from peer /api/login/timestamp)
   * @param {string} [options.accountId] - Explicit NEAR account for outbound login when token id absent
   * @param {string} [options.timestampPath] - Timestamp endpoint path (default /api/login/timestamp)
   * @returns {Promise<Object>} Login result
   */
  async function login_server(config_own_rodit, options = {}) {
    const requestId = ulid();
    const startTime = Date.now();
    const method = "login_server";

    const own_rodit = config_own_rodit?.own_rodit;

    logger.info("Starting login_server process", {
      component: "AuthenticationService",
      method,
      requestId,
      roditId: own_rodit?.token_id,
    });

    try {
      logger.debug("Retrieved config from state manager", {
        component: "AuthenticationService",
        method,
        requestId,
        hasConfig: !!config_own_rodit,
        api_ep: config_own_rodit?.apiendpoint,
      });

      if (!config_own_rodit) {
        const duration = Date.now() - startTime;

        logger.error("Client configuration not initialized", {
          component: "AuthenticationService",
          method,
          requestId,
          duration,
          errorCode: "CONFIG_NOT_INITIALIZED",
        });

        logger.metric("login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: "CONFIG_NOT_INITIALIZED",
        });
        logger.metric("login_errors_total", 1, {
          component: "AuthenticationService",
          error: "CONFIG_NOT_INITIALIZED",
        });

        return { error: "Error 0111: Client configuration not initialized" };
      }

      const apiendpoint = config_own_rodit.own_rodit?.metadata?.subjectuniqueidentifier_url;
      const loginPath =
        options.loginPath ??
        config_own_rodit.login_rodit_path ??
        config.get("LOGIN_RODIT_PATH", "/api/login");
      const loginUrl = buildLoginUrl(apiendpoint, loginPath);

      logger.info("Resolved API endpoint for login_server", {
        component: "AuthenticationService",
        method,
        requestId,
        apiEndpoint: apiendpoint,
        loginUrl,
        source: config_own_rodit.own_rodit?.metadata?.subjectuniqueidentifier_url ? "metadata" : "config",
      });

      const roditid = normalizeOptionalLoginString(own_rodit?.token_id);
      const { timestamp, error: timestampError, errorCode: timestampErrorCode } =
        await resolveServerLoginTimestamp(apiendpoint, options);
      const accountid = normalizeOptionalServerAccountId(options.accountId);

      if (timestamp === null) {
        return {
          error: timestampError || "Missing or invalid options.timestamp",
          errorCode: timestampErrorCode || "INVALID_LOGIN_TIMESTAMP",
          failureReason: timestampErrorCode || "INVALID_LOGIN_TIMESTAMP",
          requestId
        };
      }

      const hasRoditId = roditid.length > 0;
      const hasAccountId = accountid.length > 0;

      if (hasRoditId === hasAccountId) {
        return {
          error: "Provide exactly one signing identifier: own_rodit.token_id or options.accountId",
          errorCode: "LOGIN_IDENTIFIER_AMBIGUOUS",
          failureReason: "LOGIN_IDENTIFIER_AMBIGUOUS",
          requestId
        };
      }

      logger.debug("Preparing authentication data", {
        component: "AuthenticationService",
        method,
        requestId,
        api_ep: apiendpoint,
        roditId: roditid,
        accountId: accountid,
        timestamp,
      });

      const timeString = await unixTimeToDateString(timestamp);

      const signatureIdentifier = hasRoditId ? roditid : accountid;
      const signatureIdentifierandtimestamp = new TextEncoder().encode(
        signatureIdentifier + timeString
      );

      logger.debug("Generating signature", {
        component: "AuthenticationService",
        method,
        requestId,
        hasPrivateKey: !!config_own_rodit.own_rodit_bytes_private_key,
        signatureIdentifier,
      });

      const own_rodit_bytes_signature = nacl.sign.detached(
        signatureIdentifierandtimestamp,
        config_own_rodit.own_rodit_bytes_private_key
      );

      const roditid_base64url_signature = Buffer.from(
        own_rodit_bytes_signature
      ).toString("base64url");

      const requestBody = {
        timestamp,
        roditid_base64url_signature,
      };

      if (hasRoditId) {
        requestBody.roditid = roditid;
      }

      if (hasAccountId) {
        requestBody.accountid = accountid;
      }

      logger.debug("Sending login request", {
        component: "AuthenticationService",
        method,
        requestId,
        roditid,
        accountId: accountid,
        timestamp,
        signatureLength: roditid_base64url_signature?.length,
        apiEndpoint: loginUrl,
      });

      const response = await fetch(loginUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "RODiT-SDK",
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const duration = Date.now() - startTime;

        let errorDetails = null;
        let responseText = '';
        try {
          const text = await response.text();
          responseText = text;
          errorDetails = JSON.parse(text);
        } catch (parseError) {
          // If JSON parsing fails, continue with basic error
          logger.debug("Failed to parse error response as JSON", {
            component: "AuthenticationService",
            method: "login_server",
            requestId,
            responseText: responseText.substring(0, 500),
            parseError: parseError.message
          });
        }

        const apiNested = errorDetails?.error && typeof errorDetails.error === "object"
          ? errorDetails.error
          : null;
        const resolvedCode =
          apiNested?.code ||
          apiNested?.details?.failureReason ||
          errorDetails?.errorCode ||
          errorDetails?.failureReason ||
          errorDetails?.code;
        const resolvedMessage =
          apiNested?.message ||
          errorDetails?.message ||
          errorDetails?.failureMessage ||
          "Login failed";

        logger.error("Login request failed", {
          component: "AuthenticationService",
          method: "login_server",
          requestId,
          duration,
          status: response.status,
          statusText: response.statusText,
          errorCode: resolvedCode,
          errorMessage: resolvedMessage,
          failureReason: apiNested?.details?.failureReason || errorDetails?.failureReason,
          responseText: responseText.substring(0, 500),
          fullErrorDetails: errorDetails
        });

        logger.metric("login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: resolvedCode || "HTTP_ERROR",
          status: response.status,
        });
        logger.metric("login_errors_total", 1, {
          component: "AuthenticationService",
          error: resolvedCode || "HTTP_ERROR",
          status: response.status,
        });

        return {
          error: resolvedMessage,
          errorCode: resolvedCode || "HTTP_ERROR",
          failureReason: apiNested?.details?.failureReason || errorDetails?.failureReason,
          status: response.status,
          requestId
        };
      }

      const data = await response.json();
      let jwt_token = data.jwt_token;

      try {
        const { decodeJwt } = await getJose();
        const unverifiedPayload = decodeJwt(jwt_token);
        const peerRoditId = unverifiedPayload.rodit_id;

        const peer_rodit = await nearorg_rpc_tokenfromroditid(peerRoditId);

        const validationResult = await validate_jwt_token_be(
          jwt_token,
          peer_rodit,
          RELAXED_SESSION_VALIDATION_OPTIONS
        );

        if (!validationResult.valid && validationResult.errorCode) {
          const duration = Date.now() - startTime;

          logger.error("Server JWT validation failed with detailed error", {
            component: "AuthenticationService",
            method,
            requestId,
            duration,
            errorCode: validationResult.errorCode,
            errorMessage: validationResult.errorMessage,
            error: validationResult.error,
          });

          logger.metric("login_duration_ms", duration, {
            component: "AuthenticationService",
            success: false,
            error: validationResult.errorCode,
          });
          logger.metric("login_errors_total", 1, {
            component: "AuthenticationService",
            error: validationResult.errorCode,
          });

          return {
            error: validationResult.errorMessage || validationResult.error || "Server validation failed",
            errorCode: validationResult.errorCode,
            failureReason: validationResult.errorCode,
            validationError: validationResult.error,
            requestId
          };
        }

        const peer_base64url_jwk_public_key = Buffer.from(peer_rodit.owner_id, "hex").toString("base64url");
        await stateManager.setPeerBase64urlJwkPublicKey(peer_base64url_jwk_public_key);
        // Inbound webhooks are verified against the key each webhook advertises
        // and authorized by binding to the session opened here, so there is no
        // per-peer key registry to populate.

        logger.debug("Peer public key set in state manager", {
          component: "AuthenticationService",
          method,
          requestId,
          peerRoditId: peer_rodit.token_id,
          keyLength: peer_base64url_jwk_public_key.length
        });
      } catch (validationError) {
        const duration = Date.now() - startTime;

        logger.error("JWT validation failed", {
          component: "AuthenticationService",
          method,
          requestId,
          duration,
          errorMessage: validationError.message,
          stack: validationError.stack,
        });

        logger.metric("login_duration_ms", duration, {
          component: "AuthenticationService",
          success: false,
          error: "JWT_VALIDATION_FAILED",
        });
        logger.metric("login_errors_total", 1, {
          component: "AuthenticationService",
          error: "JWT_VALIDATION_FAILED",
        });

        throw new Error(
          `Error 039: Server validation failed: ${validationError.message}`
        );
      }

      const duration = Date.now() - startTime;
      logger.info("Login successful", {
        component: "AuthenticationService",
        method,
        requestId,
        duration,
        api_ep: apiendpoint,
      });

      logger.metric("login_duration_ms", duration, {
        component: "AuthenticationService",
        success: true,
      });
      logger.metric("successful_logins_total", 1, {
        component: "AuthenticationService",
        apiEndpoint: apiendpoint,
      });

      return {
        jwt_token,
        apiendpoint,
        requestId,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error("Login failed", {
        component: "AuthenticationService",
        method,
        requestId,
        duration,
        errorMessage: error.message,
        stack: error.stack,
      });

      logger.metric("login_duration_ms", duration, {
        component: "AuthenticationService",
        success: false,
        error: error.constructor.name,
      });
      logger.metric("login_errors_total", 1, {
        component: "AuthenticationService",
        error: error.constructor.name,
      });

      return {
        error: "Failed to login to server",
        requestId,
      };
    }
  }

/**
 * Handle server logout - invalidates JWT token and closes session
 *
 * @param {string} jwt_token - JWT token to invalidate
 * @returns {Promise<Object>} Logout result with termination token
 */
async function logout_server(jwt_token) {
  const requestId = ulid();
  const startTime = Date.now();
  
  // 1. Validate JWT token parameter
  if (!jwt_token) {
    return { success: false, error: "No JWT token provided", requestId };
  }

  // 2. Get API endpoint (same as login_server / account-based server login)
  const config_own_rodit = stateManager.getConfigOwnRodit();
  const apiendpoint = config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url;
  
  // 3. Make fetch call to external server
  const response = await fetch(apiendpoint + "/api/sessions/logout", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${jwt_token}`,
      "User-Agent": "RODiT-SDK",
    },
    body: JSON.stringify({
      reason: "User initiated logout"
    }),
  });

  // 4. Handle response
  if (!response.ok) {
    return {
      success: false,
      error: `Logout request failed: ${response.status} ${response.statusText}`,
      requestId
    };
  }

  // 5. Return server response
  const logoutData = await response.json();
  return {
    ...logoutData,
    requestId
  };
}


// Export the class directly (will be instantiated in rodit.js)
module.exports = {authenticate_apicall,authenticate_logout,login_server,login_portal,login_client,login_client_withnep413,logout_client,logout_server};
