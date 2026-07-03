/**
 * Webhook event handling
 * Copyright (c) 2026 Discernible IO. All rights reserved.
 */

// webhookhandlermw.js
// Reusable webhook handler for RODiT SDK

const crypto = require("crypto");
const https = require("https");
const { Agent } = require("undici");
const config = require('../../services/configsdk');
const { isStrictEnvironment, getNodeEnv } = require('../../services/env');
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const { ulid } = require("ulid");
const { sendError } = require("../../services/error-response");
const nacl = require("tweetnacl");
const stateManager = require("../blockchain/statemanager");
const { sessionManager } = require("../auth/sessionmanager");
const { authenticate_webhook } = require("../auth/authentication");

// ---------------------------------------------------------------------------
// Webhook identity + session helpers
// ---------------------------------------------------------------------------
// A webhook is a one-way POST whose only proof of origin is an Ed25519
// signature. The signer's public key travels WITH the webhook: the implicit
// account (hex of the key) and/or the base64url key are advertised in headers.
// Verification uses that key; authorization then binds it to a live session
// opened at login (see createWebhookAuthenticationMiddleware). There is nothing
// to "resolve" from local state, so these are plain extraction helpers.

const IMPLICIT_ACCOUNT_RE = /^[0-9a-f]{64}$/;

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isImplicitAccount(tokenId) {
  return IMPLICIT_ACCOUNT_RE.test(normalizeString(tokenId).toLowerCase());
}

function implicitAccountToBase64urlKey(tokenId) {
  const hex = normalizeString(tokenId).toLowerCase();
  if (!IMPLICIT_ACCOUNT_RE.test(hex)) return null;
  return Buffer.from(hex, "hex").toString("base64url");
}

function base64urlKeyToImplicitAccount(base64urlKey) {
  const key = normalizeString(base64urlKey);
  if (!key) return null;
  try {
    const hex = Buffer.from(key, "base64url").toString("hex");
    return IMPLICIT_ACCOUNT_RE.test(hex) ? hex : null;
  } catch {
    return null;
  }
}

function headerValue(headers, name) {
  if (!headers) return "";
  const raw = headers[name] ?? headers[name.toLowerCase()];
  if (typeof raw === "string") return raw.trim();
  if (Array.isArray(raw) && raw.length > 0) return String(raw[0]).trim();
  return "";
}

function parseWebhookPayload(rawPayload, parsedBody) {
  if (parsedBody && typeof parsedBody === "object") return parsedBody;
  if (typeof rawPayload === "string" && rawPayload.trim()) {
    try {
      return JSON.parse(rawPayload);
    } catch {
      return null;
    }
  }
  return null;
}

function sessionIdFromPayload(payload) {
  if (!payload || typeof payload !== "object") return "";
  const nested =
    payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)
      ? payload.data
      : null;
  return (
    normalizeString(payload.session_id) ||
    (nested && normalizeString(nested.session_id)) ||
    ""
  );
}

/**
 * Extract the session id an inbound webhook is correlated with.
 *
 * The value carried in the SIGNED payload is authoritative because it is covered
 * by the Ed25519 signature (payload + timestamp). The x-rodit-session-id header
 * is only a pre-parse convenience mirror and is used as a fallback. Callers that
 * need a trusted value should read this only after the signature has verified.
 *
 * @param {Object} params
 * @param {Object} [params.headers] Incoming request headers.
 * @param {string} [params.rawPayload] Raw request body (string).
 * @param {Object} [params.parsedBody] Pre-parsed body, if available.
 * @returns {string} The session id, or "" when none is present.
 */
function extractWebhookSessionId(params = {}) {
  const { headers, rawPayload, parsedBody } = params;
  const payload = parseWebhookPayload(rawPayload, parsedBody);
  const fromPayload = sessionIdFromPayload(payload);
  if (fromPayload) return fromPayload;
  return headerValue(headers, "x-rodit-session-id");
}

/**
 * Extract the Ed25519 public key an inbound webhook must be verified against,
 * taken directly from the identity the webhook advertises. There is no local
 * lookup: the key IS the identifier (the implicit account is the hex of the
 * key). Authorization — proving that key belongs to a peer we logged in with —
 * is enforced separately by binding to a live session.
 *
 * The signer key is carried in two mutually exclusive encodings of the same
 * identity: `X-Rodit-Implicit-Account` (hex, authoritative and preferred) and
 * `X-Rodit-Public-Key` (base64url, used only when the implicit account is
 * absent). Both are emitted by `send_webhook`. The chosen encoding is reported
 * in `source` so the decision is observable in logs.
 *
 * @param {Object} [headers] Incoming request headers.
 * @returns {{ key: string|null, source: string, implicitAccount: string }}
 */
function extractWebhookSignerKey(headers) {
  const advertisedKey = headerValue(headers, "x-rodit-public-key");
  const implicit = headerValue(headers, "x-rodit-implicit-account");

  if (isImplicitAccount(implicit)) {
    const derived = implicitAccountToBase64urlKey(implicit);
    // When the sender also advertises the raw key it must agree with the
    // implicit account; a mismatch means a buggy or spoofing sender.
    if (advertisedKey) {
      const advertisedImplicit = base64urlKeyToImplicitAccount(advertisedKey);
      if (advertisedImplicit && advertisedImplicit !== implicit.toLowerCase()) {
        return { key: null, source: "implicit_mismatch", implicitAccount: implicit.toLowerCase() };
      }
    }
    return { key: derived, source: "implicit_account", implicitAccount: implicit.toLowerCase() };
  }

  // Only the raw key was advertised: its identity is derived from the key.
  if (advertisedKey) {
    const advertisedImplicit = base64urlKeyToImplicitAccount(advertisedKey);
    if (advertisedImplicit) {
      return { key: advertisedKey, source: "advertised_key", implicitAccount: advertisedImplicit };
    }
  }

  return { key: null, source: "unresolved", implicitAccount: "" };
}

/**
 * Create a raw body parser middleware specifically for webhook endpoints
 * This preserves the raw body for signature verification
 * @returns {Function} Express middleware
 */
function createRawBodyParser() {
  return (req, res, next) => {
    if (req.headers['content-type'] !== 'application/json') {
      const requestId = req.requestId || req.headers['x-request-id'] || ulid();
      return sendError(res, {
        statusCode: 415,
        requestId,
        code: 'UNSUPPORTED_MEDIA_TYPE',
        message: 'Only application/json is supported'
      });
    }
    
    let data = '';
    req.setEncoding('utf8');
    
    req.on('data', (chunk) => {
      data += chunk;
    });
    
    req.on('end', () => {
      // Store the raw body for signature verification
      req.rawBody = data;
      
      // Parse JSON for convenience
      try {
        req.body = JSON.parse(data);
        next();
      } catch (e) {
        const requestId = req.requestId || req.headers['x-request-id'] || ulid();
        return sendError(res, {
          statusCode: 400,
          requestId,
          code: 'INVALID_JSON_PAYLOAD',
          message: 'Invalid JSON payload'
        });
      }
    });
  };
}

/**
 * Create middleware for webhook request processing
 * Webhooks use digital signature authentication only - no API tokens needed
 * @returns {Function} Express middleware
 */
function createWebhookProcessingMiddleware() {
  return (req, res, next) => {
    // Mark this as a webhook request for logging purposes
    req.isWebhookRequest = true;
    next();
  };
}

/**
 * Create middleware that extracts the signer's public key from the inbound
 * webhook and attaches it to the request for signature verification.
 * @returns {Function} Express middleware
 */
function createPublicKeyMiddleware() {
  return async (req, res, next) => {
    const requestId = crypto.randomUUID();
    const logContext = {
      component: "WebhookHandler",
      requestId,
      apiEndpoint: req.path,
      method: req.method,
      headers: Object.keys(req.headers),
      hasSignature: !!req.headers["x-signature"],
      hasTimestamp: !!req.headers["x-timestamp"],
    };

    try {
      // The signer's public key travels with the webhook itself (implicit
      // account = hex of the key). Extract it directly; each webhook is
      // self-identifying, so reception is correct even when connected to many
      // peers. Trust that the key belongs to a known peer is established later
      // by binding to a session (createWebhookAuthenticationMiddleware).
      const resolution = extractWebhookSignerKey(req.headers);
      const peerBase64urlJwkPublicKey = resolution.key;

      // Correlate to the originating session (authoritative once the signature
      // verifies downstream, since it is carried in the signed payload). Exposed
      // on the request so handlers can link the webhook to a known session.
      req.webhook_session_id = extractWebhookSessionId({
        headers: req.headers,
        rawPayload: req.rawBody,
        parsedBody: req.body,
      });

      if (peerBase64urlJwkPublicKey) {
        logger.debugWithContext("Extracted webhook signer key", {
          ...logContext,
          source: resolution.source,
          implicitAccount: resolution.implicitAccount
        });
      }

      // If the public key is not available and we're not in test mode, return an error
      if (!peerBase64urlJwkPublicKey) {
        logger.warnWithContext("Webhook signer public key not present in request", logContext);
        
        // On main, we need the key
        if (isStrictEnvironment()) {
          logger.errorWithContext("Webhook signer public key not present in main environment", logContext);
          return sendError(res, {
            statusCode: 500,
            requestId,
            code: "PEER_KEY_UNAVAILABLE",
            message: "Peer public key not available"
          });
        }
        
        // In development or test, we'll continue without the key and skip verification
        logger.infoWithContext("Continuing without webhook signer key in non-main environment", {
          ...logContext,
          environment: getNodeEnv()
        });
      }
      
      if (peerBase64urlJwkPublicKey) {
        // Log that we're using the signer key advertised by the webhook
        logger.infoWithContext("Using webhook signer public key from request", {
          ...logContext,
          keyFormat: "JWK",
          keyFound: true
        });
        
        try {
          logger.debugWithContext("Processing peer public key", {
            ...logContext,
            keyLength: peerBase64urlJwkPublicKey ? peerBase64urlJwkPublicKey.length : 0,
            keyFormat: "base64url_encoded_hex"
          });
          
          // The key is already in base64url format and should be decoded directly to bytes
          req.peer_bytes_ed25519_public_key = new Uint8Array(
            Buffer.from(peerBase64urlJwkPublicKey, "base64url")
          );
          req.server_bytes_ed25519_public_key = req.peer_bytes_ed25519_public_key;
          req.server_public_key_base64url = peerBase64urlJwkPublicKey;

          logger.debugWithContext("Processed peer public key", {
            ...logContext,
            keyLength: req.peer_bytes_ed25519_public_key.length,
            keyFormat: "base64url_decoded_to_bytes"
          });
        } catch (jwkError) {
          logger.errorWithContext("Error converting JWK peer public key", {
            ...logContext,
            error: jwkError.message
          });
          return sendError(res, {
            statusCode: 500,
            requestId,
            code: "PEER_KEY_PROCESSING_ERROR",
            message: "Error processing peer public key",
            details: { cause: jwkError.message }
          });
        }
      }
      
      next();
    } catch (error) {
      logger.errorWithContext("Error extracting server public key", {
        ...logContext,
        error: error.message,
        stack: error.stack,
      });
      return sendError(res, {
        statusCode: 500,
        requestId,
        code: "SERVER_CONFIG_ERROR",
        message: "Server configuration error"
      });
    }
  };
}

/**
 * Create middleware to authenticate webhook requests
 * @returns {Function} Express middleware
 */
function createWebhookAuthenticationMiddleware() {
  return async (req, res, next) => {
    const requestId = crypto.randomUUID();
    const logContext = {
      component: "WebhookHandler",
      requestId,
      apiEndpoint: req.path,
      method: req.method,
      headers: Object.keys(req.headers),
      bodyKeys: Object.keys(req.jsonBody || req.body || {}),
      bodySize: req.jsonBody ? JSON.stringify(req.jsonBody).length : 0,
    };

    try {
      const signature_hex_ofpayload = req.headers["x-signature"];
      const timestamp = req.headers["x-timestamp"];
      
      // Use the raw body that was captured by our middleware
      const payload = req.rawBody;
      
      if (!signature_hex_ofpayload || !timestamp || !payload) {
        logger.debugWithContext("Missing required webhook authentication parameters", {
          ...logContext,
          hasSignature: !!signature_hex_ofpayload,
          hasTimestamp: !!timestamp,
          hasPayload: !!payload
        });
        return sendError(res, {
          statusCode: 400,
          requestId,
          code: 'MISSING_AUTH_PARAMS',
          message: "Missing required authentication parameters"
        });
      }
      
      // Log the payload hash and signature for debugging
      const payloadHash = crypto
        .createHash("sha256")
        .update(payload)
        .digest("hex");
      
      logger.debugWithContext("Webhook payload hash and signature", {
        ...logContext,
        payloadHash: payloadHash,
        payloadWithTimestamp: payload + (timestamp || ''),
        payloadWithTimestampHash: crypto
          .createHash("sha256")
          .update(payload + (timestamp || ''))
          .digest("hex"),
        signature: signature_hex_ofpayload,
        timestamp: timestamp
      });
      
      // Update log context with body info
      if (Array.isArray(req.body)) {
        logContext.bodyIsArray = true;
        logContext.bodyLength = req.body.length;
      } else {
        logContext.bodyIsArray = false;
        logContext.bodyKeys = Object.keys(req.body || {});
      }
      
      logContext.bodySize = payload.length;
      logContext.hasSignature = !!signature_hex_ofpayload;
      logContext.hasTimestamp = !!timestamp;
      
      // Check if we have the server's public key
      if (!req.server_public_key_base64url) {
        // In test environments or with bypass flag, we might want to bypass verification
        const isTestEnv = String(config.get('NODE_ENV', 'development')).toLowerCase() === 'test';
        const bypassWebhookVerification = config.get('SECURITY_OPTIONS.BYPASS_WEBHOOK_VERIFICATION', false) === true;
        if (isTestEnv || bypassWebhookVerification) {
          logger.warnWithContext("Bypassing webhook authentication in test environment", logContext);
          return next();
        }
        
        return sendError(res, {
          statusCode: 500,
          requestId,
          code: "SERVER_CONFIG_ERROR",
          message: "Server configuration error"
        });
      }
      
      // Authenticate the webhook using the server's public key
      logger.debugWithContext("Authenticating webhook signature", logContext);
      const publicKeyBase64url = req.server_public_key_base64url;
      
      // Call the authentication function with proper error handling
      let authResult;
      try {
        authResult = await authenticate_webhook(
          payload,
          signature_hex_ofpayload,
          timestamp,
          publicKeyBase64url
        );
      } catch (authError) {
        return sendError(res, {
          statusCode: 500,
          requestId,
          code: "WEBHOOK_AUTH_ERROR",
          message: "Webhook authentication error",
          details: { cause: authError.message }
        });
      }

      if (!authResult.isValid) {
        logger.warnWithContext("Invalid webhook signature", {
          ...logContext,
          result: 'failure',
          reason: 'Invalid webhook signature',
          error: authResult.error?.message,
          code: authResult.error?.code || 'UNKNOWN_ERROR'
        });
        return sendError(res, {
          statusCode: 401,
          requestId,
          code: authResult.error?.code || 'WEBHOOK_SIGNATURE_INVALID',
          message: authResult.error?.message || "Invalid webhook signature"
        });
      }

      // Authorization gate (signer <-> session binding).
      //
      // A valid signature only proves the sender holds the private key for the
      // identity it advertised; it does NOT prove that identity is a peer we
      // established a session with. Bind the verified signer to a live session
      // opened at login: the session_id carried in the (now signature-verified)
      // payload must map to an active session whose ownerId equals the signer's
      // implicit account (hex of the public key the signature verified against).
      // This rejects a made-up key that is internally consistent but unrelated
      // to any peer we logged in with.
      const bypassSessionBinding =
        String(config.get('NODE_ENV', 'development')).toLowerCase() === 'test' ||
        config.get('SECURITY_OPTIONS.BYPASS_WEBHOOK_VERIFICATION', false) === true;

      if (!bypassSessionBinding) {
        const sessionId =
          req.webhook_session_id ||
          extractWebhookSessionId({
            headers: req.headers,
            rawPayload: req.rawBody,
            parsedBody: req.body,
          });

        if (!sessionId) {
          logger.warnWithContext("Webhook rejected: not associated with a session", {
            ...logContext,
            result: 'failure',
            reason: 'missing_session_id',
          });
          return sendError(res, {
            statusCode: 401,
            requestId,
            code: 'WEBHOOK_SESSION_REQUIRED',
            message: "Webhook is not associated with a session",
          });
        }

        // Derive the verified signer's implicit account from the exact public
        // key the signature was checked against.
        let signerImplicitAccount = '';
        try {
          signerImplicitAccount = Buffer.from(publicKeyBase64url, 'base64url')
            .toString('hex')
            .toLowerCase();
        } catch (implicitError) {
          signerImplicitAccount = '';
        }

        if (!sessionManager || typeof sessionManager.getSession !== 'function') {
          logger.errorWithContext("Session manager unavailable for webhook binding check", logContext);
          return sendError(res, {
            statusCode: 500,
            requestId,
            code: "SERVER_CONFIG_ERROR",
            message: "Server configuration error",
          });
        }

        const session = await sessionManager.getSession(sessionId);
        const nowSec = Math.floor(Date.now() / 1000);
        const sessionLive =
          !!session &&
          (session.status ? session.status === 'active' : true) &&
          (!session.expiresAt || session.expiresAt > nowSec);

        if (!sessionLive) {
          logger.warnWithContext("Webhook rejected: session unknown or expired", {
            ...logContext,
            result: 'failure',
            reason: 'session_not_live',
            sessionId,
          });
          return sendError(res, {
            statusCode: 401,
            requestId,
            code: 'WEBHOOK_SESSION_INVALID',
            message: "Webhook session is unknown or expired",
          });
        }

        const sessionOwner = String(session.ownerId || '').toLowerCase();
        if (!sessionOwner || !signerImplicitAccount || sessionOwner !== signerImplicitAccount) {
          logger.warnWithContext("Webhook rejected: signer does not match session owner", {
            ...logContext,
            result: 'failure',
            reason: 'signer_session_mismatch',
            sessionId,
            signerImplicitAccount,
            sessionOwner,
          });
          return sendError(res, {
            statusCode: 403,
            requestId,
            code: 'WEBHOOK_SIGNER_SESSION_MISMATCH',
            message: "Webhook signer is not the peer bound to this session",
          });
        }

        // Expose the validated binding for downstream handlers.
        req.webhook_session = session;
        req.webhook_session_id = sessionId;
        req.webhook_signer_implicit_account = signerImplicitAccount;
      }

      logger.infoWithContext("Webhook authenticated successfully", {
        ...logContext,
        authDuration: authResult.duration,
        component: "WebhookHandler"
      });
      
      // Store authentication result for later use
      req.webhookAuthResult = authResult;
      
      next();
    } catch (error) {
      logger.errorWithContext("Error authenticating webhook", {
        ...logContext,
        error: error.message,
        stack: error.stack
      });
      return sendError(res, {
        statusCode: 500,
        requestId,
        code: "WEBHOOK_AUTHENTICATION_ERROR",
        message: "Webhook authentication error"
      });
    }
  };
}

/**
 * Process a webhook event and extract its data
 * @param {Object} req - Express request object
 * @param {Object} logContext - Logging context
 * @returns {Object} Extracted event data
 */
function processWebhookEvent(req, logContext = {}) {
  try {
    // Check if the body is valid before attempting to destructure
    if (!req.body || typeof req.body !== 'object') {
      logger.errorWithContext("Invalid webhook payload format", {
        ...logContext,
        component: "WebhookHandler",
        bodyType: typeof req.body,
        bodyIsNull: req.body === null,
        contentType: req.headers['content-type']
      });
      return { error: "Invalid payload format" };
    }
    
    const { event, data, isError, timestamp: payloadTimestamp, requestId: payloadRequestId } = req.body;

    const eventType = typeof event === "string" ? event.trim() : "";

    if (!eventType) {
      logger.errorWithContext("Webhook payload missing event type", {
        ...logContext,
        component: "WebhookHandler",
        rawEventValue: event,
        hasEventField: Object.prototype.hasOwnProperty.call(req.body, "event"),
      });
      return { error: "Event type is required but was not provided" };
    }

    logger.infoWithContext("Processing webhook payload", {
      ...logContext,
      component: "WebhookHandler",
      event: eventType,
      eventType,
      isError,
      payloadTimestamp,
      payloadRequestId,
      dataKeys: data ? Object.keys(data) : [],
      dataType: typeof data,
      dataSize: data ? JSON.stringify(data).length : 0
    });

    return {
      type: eventType,
      name: eventType,
      event: eventType,
      data,
      isError,
      timestamp: payloadTimestamp,
      requestId: payloadRequestId,
      error: null
    };
  } catch (error) {
    logger.debugWithContext("Error processing webhook payload", {
      ...logContext,
      component: "WebhookHandler",
      error: error.message,
      stack: error.stack
    });
    return { error: error.message };
  }
}

/**
 * Create a complete webhook handler for Express.
 *
 * The middleware is self-contained: the signer key is extracted from each
 * inbound webhook and the shared state manager / session manager are imported
 * directly, so no constructor arguments are required.
 *
 * @returns {Object} Webhook handler with middleware and utilities
 */
function createWebhookHandler() {
  const rawBodyParser = createRawBodyParser();
  const webhookProcessingMiddleware = createWebhookProcessingMiddleware();
  const publicKeyMiddleware = createPublicKeyMiddleware();
  const authenticationMiddleware = createWebhookAuthenticationMiddleware();
  
  return {
    // Middleware
    rawBodyParser,
    webhookProcessingMiddleware,
    publicKeyMiddleware,
    authenticationMiddleware,
    
    // Utility functions
    processWebhookEvent,
    
    // Combined middleware for easy setup
    middleware: [
      rawBodyParser,
      webhookProcessingMiddleware,
      publicKeyMiddleware,
      authenticationMiddleware
    ],
    
    // Helper to apply middleware based on route
    applyMiddleware: (app, express, options = {}) => {
      const endpoints = Array.isArray(options.endpoints) && options.endpoints.length > 0
        ? options.endpoints
        : ['/webhook'];
      const normalizedEndpoints = endpoints.map((endpoint) => {
        const endpointString = String(endpoint || '/webhook');
        return endpointString.startsWith('/') ? endpointString : `/${endpointString}`;
      });
      const endpointSet = new Set(normalizedEndpoints);

      // Apply raw body parser only to configured webhook routes
      app.use((req, res, next) => {
        if (endpointSet.has(req.path)) {
          rawBodyParser(req, res, next);
        } else {
          express.json()(req, res, next);
        }
      });
      
      // Apply webhook processing + key extraction middleware to all webhook routes
      for (const endpoint of normalizedEndpoints) {
        app.use(endpoint, webhookProcessingMiddleware);
        app.use(endpoint, publicKeyMiddleware);
      }
      
      return app;
    }
  };
}

/**
 * Resolve the session id to stamp into an outbound webhook so the receiver can
 * correlate it with the session opened at login.
 *
 * Resolution order:
 *   1. options.sessionId — explicit override (most reliable for multi-peer).
 *   2. req.user.session_id — the authenticated peer JWT context (set by the auth
 *      middleware when replying to a request).
 *   3. req.session_id — session id attached directly to the request.
 *   4. Session storage — the JWT issuer (login_client) keeps a session per peer
 *      keyed by that peer's roditId. Given the recipient's identity
 *      (options.sessionRoditId / options.peerTokenId) we resolve the shared
 *      session id from the SessionManager without needing any request context.
 *
 * @param {Object} options
 * @param {Object} req
 * @returns {Promise<string>} The resolved session id, or "" if none.
 */
async function resolveOutboundWebhookSessionId(options = {}, req = null) {
  const explicit =
    (options && typeof options.sessionId === "string" && options.sessionId.trim()) ||
    (req && req.user && typeof req.user.session_id === "string" && req.user.session_id.trim()) ||
    (req && typeof req.session_id === "string" && req.session_id.trim()) ||
    "";
  if (explicit) return explicit;

  const roditId =
    (options && typeof options.sessionRoditId === "string" && options.sessionRoditId.trim()) ||
    (options && typeof options.peerTokenId === "string" && options.peerTokenId.trim()) ||
    "";
  if (!roditId || !sessionManager || typeof sessionManager.findSessionsByRoditId !== "function") {
    return "";
  }

  try {
    const sessions = await sessionManager.findSessionsByRoditId(roditId);
    if (!Array.isArray(sessions) || sessions.length === 0) return "";
    const nowSec = Math.floor(Date.now() / 1000);
    const usable = sessions
      .filter((s) => s && s.id)
      // Stamp the session the recipient holds *as a client*, i.e. one this peer
      // issued as a server. Exclude sessions this peer merely recorded as a
      // client (origin === "client") so mutual peers don't cross-stamp.
      .filter((s) => (s.origin ? s.origin !== "client" : true))
      .filter((s) => (s.status ? s.status === "active" : true))
      .filter((s) => !s.expiresAt || s.expiresAt > nowSec)
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    return usable.length > 0 ? String(usable[0].id) : "";
  } catch (sessionLookupError) {
    logger.debugWithContext("Session storage lookup for webhook failed", {
      component: "WebhookHandler",
      method: "send_webhook",
      roditId,
      error: sessionLookupError.message
    });
    return "";
  }
}

/**
    * Send a webhook notification with comprehensive logging
    *
    * @param {Object} data - Webhook envelope. Expected shape: { event: string, data?: any, isError?: boolean }
    * @param {Object} req - Express request object (optional)
    * @param {Object} options - Options object (optional)
    * @param {string} options.endpoint - Target endpoint path (e.g., '/webhook', '/hooks/wake', '/hooks/agent'). Defaults to '/webhook'
    * @param {string} [options.sessionId] - Explicit session id to correlate this webhook with
    * @param {string} [options.sessionRoditId] - Recipient peer roditId; used to resolve the session id from session storage
    * @returns {Promise<Object>} Webhook delivery result with requestId
    */
   async function send_webhook(data, req = null, options = {}) {
     // Derive fields from envelope
     const event = data && typeof data === 'object' ? (data.event || 'generic_event') : 'generic_event';
     let isError = !!(data && data.isError);

     // Always generate a new correlation ID
     const requestId = ulid();

     // Rebind data to the actual payload object (inner data if present, else entire envelope)
     if (data && Object.prototype.hasOwnProperty.call(data, 'data')) {
       data = data.data;
     }
     const startTime = Date.now();
   
     // Create a context object for consistent logging
     const webhookContext = {
       event,
       requestId,
       isError,
       dataType: typeof data,
       operation: "webhook",
       method: "send_webhook",
       component: "WebhookHandler"
     };
   
     // Create base context for all logs in this function
     const baseContext = createLogContext("RoditAuth", "send_webhook", {
       requestId,
       event,
       isError,
       dataSize: typeof data === "object" ? JSON.stringify(data).length : "unknown"
     });
     
     // Log the webhook attempt
     logger.debugWithContext("Starting webhook delivery", baseContext);
   
     // Also log with the infoWithContext pattern used in cruda.js
     logger.infoWithContext("Sending webhook", {
       ...webhookContext,
       status: "attempt",
       eventType: event
     });
   
     try {
       // Webhook URL must come from peer JWT token only
      if (!req || !req.user || !req.user.rodit_webhookurl) {
        const duration = Date.now() - startTime;
  
        logger.warnWithContext("Peer JWT webhook URL missing", {
          ...baseContext,
          duration,
          hasReq: !!req,
          hasReqUser: !!(req && req.user),
          hasWebhookUrl: !!(req && req.user && req.user.rodit_webhookurl)
        });
  
        // Emit metrics for dashboards
        logger.metric &&
          logger.metric("webhook_delivery_duration_ms", duration, {
            component: "WebhookHandler",
            success: false,
            event,
            error: "WEBHOOK_URL_MISSING",
          });
        logger.metric &&
          logger.metric("webhook_delivery_failures_total", 1, {
            component: "WebhookHandler",
            reason: "PEER_JWT_MISSING",
            event,
          });
  
        // Log error with new logErrorWithMetrics helper
        logErrorWithMetrics(
          "Peer JWT webhook URL missing", 
          createLogContext(
            "WebhookHandler",
            "webhook_url_error",
            {
              ...webhookContext,
              status: "error"
            }
          ),
          new Error("Peer JWT webhook URL not available"),
          "webhook_error_count",
          { error_type: "peer_jwt_missing" }
        );
        
        return {
          isValid: false,
          error: {
            code: "WEBHOOK_URL_MISSING",
            message: "Webhook URL not available in peer JWT token",
            requestId,
          },
        };
      }
  
      // Use the webhook URL from the peer's JWT token
      const webhookUrl = req.user.rodit_webhookurl;
      
      // Extract endpoint from options (defaults to /webhook)
      const endpoint = options.endpoint || '/webhook';
      
      logger.debugWithContext("Using webhook URL from peer identity context", {
        ...baseContext,
        webhookSource: "peer_context",
        webhookUrl,
        endpoint
      });
   
      // Normalize base URL and endpoint so we always produce exactly one slash
      // between host and path (e.g. https://host/hooks/wake).
      const cleanWebhookUrl = webhookUrl
        .replace(/^(https?:\/\/)/, "")
        .replace(/\/+$/, "");
      const normalizedEndpoint = `/${String(endpoint || "/webhook").replace(/^\/+/, "")}`;
      const formattedWebhookUrl = `https://${cleanWebhookUrl}${normalizedEndpoint}`;
   
       logger.debugWithContext("Webhook URL details", {
         ...baseContext,
         rawWebhookUrl: webhookUrl,
         endpoint,
         formattedWebhookUrl
       });
   
       const timestamp = Date.now();
       
       // Ensure data is serializable before stringifying
       let sanitizedData;
       try {
         // Test if data can be properly serialized
         if (typeof data === 'object' && data !== null) {
           // Create a deep copy to avoid modifying the original data
           sanitizedData = JSON.parse(JSON.stringify(data));
         } else if (data === undefined || data === null) {
           // Handle null/undefined explicitly
           sanitizedData = null;
         } else if (typeof data === 'string' || typeof data === 'number' || typeof data === 'boolean') {
           // Primitive types can be used directly
           sanitizedData = data;
         } else {
           // For other types (functions, symbols, etc.), create a string representation
           sanitizedData = {
             type: typeof data,
             stringValue: String(data)
           };
         }
       } catch (serializeError) {
         // If data can't be serialized, create a simplified version
         logger.debugWithContext("Data serialization failed, creating simplified version", {
           ...baseContext,
           error: serializeError.message
         });
         
         // Create a simplified version with basic properties
         sanitizedData = {
           type: typeof data,
           summary: "Data could not be serialized to JSON",
           error: serializeError.message
         };
       }
       
       // Correlate this webhook with an existing session when one is known.
       // Resolved from the explicit option, the authenticated request context,
       // or session storage (by recipient roditId). Included in the SIGNED
       // payload below so the receiver can trust and match it.
       const webhookSessionId = await resolveOutboundWebhookSessionId(options, req);

       // Create the payload object
       const payloadObj = {
         event,
         data: sanitizedData,
         isError,
         requestId,
       };
       if (webhookSessionId) {
         payloadObj.session_id = webhookSessionId;
       }
       
       // Create the payload with consistent JSON formatting
       // Sort keys to ensure canonical representation regardless of object creation order
       const payload = JSON.stringify(payloadObj, function(key, value) {
         // Handle special numeric values consistently
         if (typeof value === 'number') {
           if (isNaN(value)) return 'NaN';
           if (value === Infinity) return 'Infinity';
           if (value === -Infinity) return '-Infinity';
         }
         return value;
       }, 0);
       
       // Ensure consistent handling of Unicode characters
       const normalizedPayload = payload.normalize('NFC');
       
       logger.debug("Preparing webhook payload", {
         component: "WebhookHandler",
         method: "send_webhook",
         requestId,
         payloadSize: normalizedPayload.length,
         event,
       });
       
       // Create the string to hash: payload + timestamp
       // This binds the timestamp to the payload for signature verification
       const payloadWithTimestamp = normalizedPayload + timestamp.toString();
       
       logger.debugWithContext("Creating payload+timestamp string for signing", {
         ...baseContext,
         payloadSize: normalizedPayload.length,
         timestampLength: timestamp.toString().length,
         combinedLength: payloadWithTimestamp.length
       });
   
       // Generate hash of payload+timestamp
       const sha256_ofpayload = crypto
         .createHash("sha256")
         .update(payloadWithTimestamp)
         .digest();
   
       // Log hash details for visibility
       logger.debug("Webhook hash details", {
         component: "WebhookHandler",
         method: "send_webhook",
         requestId,
         hashHex: sha256_ofpayload.toString('hex'),
         hashLength: sha256_ofpayload.length
       });
   
      const config_own_rodit = await stateManager.getConfigOwnRodit();
      if (!config_own_rodit || !config_own_rodit.own_rodit_bytes_private_key) {
        throw new Error("Own RODiT private key unavailable for webhook signing");
      }

      logger.debugWithContext("Creating signature", {
         ...baseContext,
         hasPrivateKey: !!config_own_rodit.own_rodit_bytes_private_key
       });
   
       // Convert private key and generate signature
       const own_rodit_private_key = new Uint8Array(
         config_own_rodit.own_rodit_bytes_private_key
       );
   
       // Log the public key from state manager
       const publicKey = stateManager.getOwnBase64urlJwkPublicKey();
       
       // Log the key in multiple formats for precise comparison
       logger.debug("Webhook signing key information", {
         component: "WebhookHandler",
         method: "send_webhook",
         requestId,
         publicKeyBase64url: publicKey,
         publicKeyHex: publicKey ? Buffer.from(publicKey, 'base64url').toString('hex') : null,
         keyLength: publicKey ? Buffer.from(publicKey, 'base64url').length : 0
       });
   
       const signatureStartTime = Date.now();
       const signature_ofpayload = nacl.sign.detached(
         sha256_ofpayload,
         own_rodit_private_key
       );
       const signatureDuration = Date.now() - signatureStartTime;
   
       // Log signature generation metrics
       logger.metric &&
         logger.metric("signature_generation_duration_ms", signatureDuration, {
           component: "WebhookHandler",
         });
   
       const signature_hex_ofpayload =
         Buffer.from(signature_ofpayload).toString("hex");
   
       // Log signature details for visibility and comparison with client logs
       logger.debugWithContext("Webhook signature details", {
         ...baseContext,
         signatureHex: signature_hex_ofpayload,
         signatureBase64: Buffer.from(signature_ofpayload).toString("base64"),
         signatureBase64url: Buffer.from(signature_ofpayload).toString("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
         signatureLength: signature_hex_ofpayload.length,
         signatureByteLength: signature_ofpayload.length
       });
       
       // Log the exact hash that was signed for comparison
       logger.debugWithContext("Webhook hash that was signed", {
         ...baseContext,
         hashHex: Buffer.from(sha256_ofpayload).toString('hex'),
         hashBase64: Buffer.from(sha256_ofpayload).toString('base64'),
         hashBase64url: Buffer.from(sha256_ofpayload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
         hashLength: sha256_ofpayload.length
       });
   
       logger.debugWithContext("Sending webhook request", {
         ...baseContext,
         webhookUrl: formattedWebhookUrl,
         timestamp: timestamp.toString(),
         payload: ['debug', 'trace'].includes(config.get('LOG_LEVEL', 'info')) ? payload : undefined, // Only log payload in debug mode
         signatureHex: signature_hex_ofpayload
       });
   
      // Prepare headers for the webhook request
      // Only include webhook-specific authentication headers (digital signature)
      // No API bearer tokens - webhook security relies on cryptographic signatures
      const headers = {
        "Content-Type": "application/json",
        "X-Signature": signature_hex_ofpayload,
        "X-Timestamp": timestamp.toString(),
        "X-Request-ID": requestId
      };

      // Advertise the signer identity so multi-peer receivers can resolve the
      // correct verification key deterministically instead of relying on a
      // single mutable "current peer" slot. The implicit account is the hex of
      // the signing Ed25519 public key and is authoritative on its own.
      try {
        if (publicKey) {
          headers["X-Rodit-Public-Key"] = publicKey;
          headers["X-Rodit-Implicit-Account"] = Buffer.from(publicKey, "base64url").toString("hex");
        }
        const ownTokenId = config_own_rodit?.own_rodit?.token_id;
        if (ownTokenId) {
          headers["X-Rodit-Token-Id"] = String(ownTokenId);
        }
      } catch (identityHeaderError) {
        logger.debugWithContext("Unable to attach signer identity headers", {
          ...baseContext,
          error: identityHeaderError.message
        });
      }

      // Mirror the (signed) session id into a header for pre-parse correlation.
      // The signed payload value remains authoritative; this is convenience only.
      if (webhookSessionId) {
        headers["X-Rodit-Session-Id"] = webhookSessionId;
      }
       
       // Log the exact headers being sent
       logger.debugWithContext("Webhook request headers", {
         ...baseContext,
         headers: headers,
         signatureHeader: signature_hex_ofpayload,
         timestampHeader: timestamp.toString()
       });
       
       // SELF-VERIFICATION: Call authenticate_webhook with the same parameters the client will use
       // This helps determine if the issue is in the signature generation/verification or in the data flow
       try {
         logger.info("Performing self-verification before sending webhook", {
           component: "WebhookHandler",
           method: "send_webhook",
           requestId
         });
         
         // Get our own public key for verification
         const publicKeyForVerification = stateManager.getOwnBase64urlJwkPublicKey();
         
         // Call authenticate_webhook with the same parameters the client will receive
         const verificationResult = await authenticate_webhook(
           payload,                  // The exact payload being sent
           signature_hex_ofpayload,  // The signature in hex format
           timestamp.toString(),     // The timestamp as a string
           publicKeyForVerification  // Our own public key for verification
         );
         
         logger.infoWithContext("Self-verification result", {
           ...baseContext,
           selfVerificationSuccess: verificationResult.isValid,
           selfVerificationError: verificationResult.error ? verificationResult.error.message : null
         });
         
         if (!verificationResult.isValid) {
           logger.warnWithContext("Self-verification failed - client verification will likely fail too", {
             ...baseContext,
             error: verificationResult.error ? verificationResult.error.message : "Unknown verification error"
           });
         }
       } catch (verificationError) {
         logErrorWithMetrics(
           "Error during self-verification",
           baseContext,
           verificationError,
           "webhook_verification_error",
           { error_type: "self_verification_error" }
         );
       }
       
       // Configure HTTPS agent to skip TLS verification if configured
      // This is necessary when webhook destinations use self-signed certificates
      // Since mutual authentication via digital signatures is already in place,
      // skipping TLS verification is safe in this context
      const skipTlsVerify = config.has('SECURITY_OPTIONS.WEBHOOK_TLS_SKIP_VERIFY') 
        ? String(config.get('SECURITY_OPTIONS.WEBHOOK_TLS_SKIP_VERIFY')).toLowerCase() === 'true'
        : false;
      
      let fetchOptions = {
        method: "POST",
        headers: headers,
        body: payload,
      };
      
      if (skipTlsVerify) {
        // Create custom undici Agent that accepts self-signed certificates
        // Node.js fetch uses undici under the hood and requires 'dispatcher' option
        const undiciAgent = new Agent({
          connect: {
            rejectUnauthorized: false
          }
        });
        fetchOptions.dispatcher = undiciAgent;
        
        logger.debugWithContext("Webhook TLS verification disabled", {
          ...baseContext,
          skipTlsVerify: true,
          reason: "SECURITY_OPTIONS.WEBHOOK_TLS_SKIP_VERIFY=true"
        });
      }
      
      // Send webhook request
      const fetchStartTime = Date.now();
      const response = await fetch(formattedWebhookUrl, fetchOptions);
      const fetchDuration = Date.now() - fetchStartTime;
   
       // Log fetch duration metrics
       logger.metric("webhook_http_request_duration_ms", fetchDuration, {
         component: "WebhookHandler",
         success: response.ok,
         status: response.status,
         event,
       });
   
       if (!response.ok) {
         const duration = Date.now() - startTime;
   
         logErrorWithMetrics(
           "Webhook delivery failed",
           {
             ...baseContext,
             duration,
             status: response.status,
             statusText: response.statusText,
             webhookUrl: formattedWebhookUrl
           },
           new Error(`HTTP ${response.status}: ${response.statusText}`),
           "webhook_delivery_error",
           { error_type: "http_error", status: response.status }
         );
   
         // Emit metrics for dashboards
         logger.metric("webhook_delivery_duration_ms", duration, {
           component: "WebhookHandler",
           success: false,
           event,
           error: "HTTP_ERROR",
           status: response.status,
         });
         logger.metric("webhook_delivery_failures_total", 1, {
           component: "WebhookHandler",
           reason: "HTTP_ERROR",
           status: response.status,
           event,
         });
   
         throw new Error(`HTTP error! status: ${response.status}`);
       }
   
       await response.text();
   
       const duration = Date.now() - startTime;
       logger.infoWithContext("Webhook delivered successfully", {
         ...baseContext,
         duration,
         webhookUrl: formattedWebhookUrl,
         status: response.status
       });
   
       // Emit metrics for dashboards
       logger.metric("webhook_delivery_duration_ms", duration, {
         component: "WebhookHandler",
         success: true,
         event,
       });
       logger.metric("successful_webhook_deliveries_total", 1, {
         component: "WebhookHandler",
         event,
       });
   
       // Removed test-mode DB recording on success
   
       // Log success with infoWithContext pattern
       logger.infoWithContext("Webhook sent successfully", {
         ...webhookContext,
         status: "success"
       });
       
       // Return success result with requestId for tracing
       return {
         isValid: true,
         message: "Webhook sent successfully",
         requestId,
         duration,
       };
     } catch (error) {
       const duration = Date.now() - startTime;
   
       logErrorWithMetrics(
         "Webhook send failed",
         {
           ...baseContext,
           duration,
           errorCode: error.code || "UNKNOWN_ERROR",
           isError,
           operation: "webhook",
           status: "failed"
         },
         error,
         "webhook_delivery_error",
         { error_type: "network_error" }
       );
   
       // Emit metrics for dashboards
       logger.metric("webhook_delivery_duration_ms", duration, {
         component: "WebhookHandler",
         success: false,
         event,
         error: error.constructor.name,
       });
       logger.metric("webhook_delivery_errors_total", 1, {
         component: "WebhookHandler",
         error: error.constructor.name,
         event,
       });
   
       // Log error with errorWithContext pattern
       logger.errorWithContext && logger.errorWithContext(
         "Webhook send failed", 
         {
           ...webhookContext,
           status: "failed",
           errorMessage: error.message
         },
         error
       );
       
       // Return error result with requestId for tracing
       return {
         isValid: false,
         error: {
           code: "WEBHOOK_SEND_ERROR",
           message: `Failed to send webhook: ${error.message}`,
           requestId,
         },
       };
     }
    }

/**
 * Base class for webhook event handlers
 */
class WebhookEventHandler {
  /**
   * Create a new webhook event handler
   * @param {Object} configuration - Configuration configuration
   */
  constructor(configuration = {}) {
    this.configuration = configuration;
  }

  /**
   * Handle a webhook event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    throw new Error("Method not implemented");
  }
}

/**
 * Handler for test configuration update events
 */
class TestConfigUpdateHandler extends WebhookEventHandler {
  /**
   * Create a new test configuration update handler
   * @param {Object} configManager - Configuration manager
   * @param {Object} configuration - Configuration configuration
   */
  constructor(configManager, configuration = {}) {
    super(configuration);
    this.configManager = configManager;
  }

  /**
   * Handle a test configuration update event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "TestConfigUpdateHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      if (!this.configManager) {
        const error = new Error("Config manager is required but not provided");
        logger.errorWithContext(error.message, logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }

      // Update configuration
      await this.configManager.updateConfig(event.data);

      logger.infoWithContext("Test configuration updated successfully", logContext);
      return {
        success: true,
        message: "Test configuration updated successfully",
      };
    } catch (error) {
      logger.errorWithContext(error.message, logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Handler for test suite execution events
 */
class TestSuiteHandler extends WebhookEventHandler {
  /**
   * Create a new test suite handler
   * @param {Function} runTestSuite - Function to run a test suite
   * @param {Object} configuration - Configuration configuration
   */
  constructor(runTestSuite, configuration = {}) {
    super(configuration);
    this.runTestSuite = runTestSuite;
  }

  /**
   * Handle a test suite execution event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "TestSuiteHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      if (!this.runTestSuite) {
        const error = new Error("runTestSuite function is required but not provided");
        logger.errorWithContext(error.message, logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }

      // Extract test configuration from event data
      const testOptions = event.data || {};
      
      // Run the test suite
      const testResults = await this.runTestSuite(testOptions);

      logger.infoWithContext("Test suite executed successfully", logContext);
      return {
        success: true,
        message: "Test suite executed successfully",
        results: testResults,
      };
    } catch (error) {
      logger.errorWithContext(error.message, logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Handler for single test execution events
 */
class SingleTestHandler extends WebhookEventHandler {
  /**
   * Create a new single test handler
   * @param {Function} runSingleTest - Function to run a single test
   * @param {Object} configuration - Configuration configuration
   */
  constructor(runSingleTest, configuration = {}) {
    super(configuration);
    this.runSingleTest = runSingleTest;
  }

  /**
   * Handle a single test execution event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "SingleTestHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      if (!this.runSingleTest) {
        const error = new Error("runSingleTest function is required but not provided");
        logger.errorWithContext(error.message, logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }

      // Extract test configuration from event data
      const testOptions = event.data || {};
      const testName = testOptions.testName;
      
      if (!testName) {
        const error = new Error("testName is required but not provided");
        logger.errorWithContext(error.message, logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }
      
      // Run the single test
      const testResults = await this.runSingleTest(testName, testOptions);

      logger.infoWithContext("Single test executed successfully", logContext);
      return {
        success: true,
        message: `Test '${testName}' executed successfully`,
        results: testResults,
      };
    } catch (error) {
      logger.errorWithContext(error.message, logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Handler for comment events
 */
class CommentEventHandler extends WebhookEventHandler {
  /**
   * Create a new comment event handler
   * @param {Object} configuration - Configuration configuration
   */
  constructor(configuration = {}) {
    super(configuration);
  }

  /**
   * Handle a comment event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "CommentEventHandler",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      // Log the comment event
      logger.infoWithContext("Comment event received", {
        ...logContext,
        eventType: event.type,
        commentId: event.data?.commentId,
        userId: event.data?.userId,
        testId: event.data?.testId,
      });

      // For now, we just acknowledge receipt of the event
      // In the future, this could store comments in a database or trigger other actions
      return {
        success: true,
        message: `Comment event '${event.type}' processed successfully`,
        eventType: event.type,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.errorWithContext(error.message, logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Factory for creating webhook event handlers
 */
class WebhookEventHandlerFactory {
  /**
   * Create a new webhook event handler factory
   * @param {Object} dependencies - Dependencies for handlers
   * @param {Object} configuration - Configuration configuration
   */
  constructor(dependencies = {}, configuration = {}) {
    this.dependencies = dependencies;
    this.configuration = configuration;
    this.handlers = new Map();
    
    // Register default handlers if dependencies are provided
    if (dependencies.configManager) {
      this.registerHandler("test_config_update", new TestConfigUpdateHandler(dependencies.configManager, configuration));
    }
    
    if (dependencies.runTestSuite) {
      this.registerHandler("run_test_suite", new TestSuiteHandler(dependencies.runTestSuite, configuration));
    }
    
    if (dependencies.runSingleTest) {
      this.registerHandler("run_single_test", new SingleTestHandler(dependencies.runSingleTest, configuration));
    }
    
    // Register comment event handlers
    const commentHandler = new CommentEventHandler(configuration);
    this.registerHandler("comment_created", commentHandler);
    this.registerHandler("comment_updated", commentHandler);
    this.registerHandler("comment_deleted", commentHandler);
    this.registerHandler("comments_listed", commentHandler);
    this.registerHandler("create_comment_error", commentHandler);
    this.registerHandler("update_comment_error", commentHandler);
    this.registerHandler("delete_comment_error", commentHandler);
    this.registerHandler("read_comment_error", commentHandler);
  }

  /**
   * Register a handler for an event type
   * @param {string} eventType - Event type
   * @param {WebhookEventHandler} handler - Event handler
   */
  registerHandler(eventType, handler) {
    this.handlers.set(eventType, handler);
  }

  /**
   * Get a handler for an event type
   * @param {string} eventType - Event type
   * @returns {WebhookEventHandler|null} Event handler or null if not found
   */
  getHandler(eventType) {
    return this.handlers.get(eventType) || null;
  }

  /**
   * Handle a webhook event
   * @param {Object} event - Event data
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<Object>} Response data
   */
  async handleEvent(event, req, res) {
    const logContext = createLogContext({
      component: "WebhookEventHandlerFactory",
      event: "handleEvent",
      requestId: req.requestId || ulid(),
      eventType: event.type,
    });

    try {
      const eventType = event.type;
      
      if (!eventType) {
        const error = new Error("Event type is required but not provided");
        logger.errorWithContext(error.message, logContext, error);
        return {
          success: false,
          error: error.message,
        };
      }
      
      const handler = this.getHandler(eventType);
      
      if (!handler) {
        logger.infoWithContext("No handler registered for webhook event type; acknowledging event", {
          ...logContext,
          eventType,
          mode: "noop-ack"
        });
        return {
          success: true,
          ignored: true,
          message: `No handler registered for event type: ${eventType}`,
          eventType
        };
      }
      
      return await handler.handleEvent(event, req, res);
    } catch (error) {
      logger.errorWithContext(error.message, logContext, error);
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

module.exports = {
  // Original exports from webhookhandlermw.js
  createRawBodyParser,
  createWebhookProcessingMiddleware,
  createPublicKeyMiddleware,
  createWebhookAuthenticationMiddleware,
  processWebhookEvent,
  createWebhookHandler,
  send_webhook,

  // Webhook identity + session helpers
  extractWebhookSignerKey,
  extractWebhookSessionId,
  isImplicitAccount,
  implicitAccountToBase64urlKey,
  base64urlKeyToImplicitAccount,

  // Added exports from eventhandler.js
  WebhookEventHandler,
  TestConfigUpdateHandler,
  TestSuiteHandler,
  SingleTestHandler,
  CommentEventHandler,
  WebhookEventHandlerFactory
};