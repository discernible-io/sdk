/**
 * Enforce per-route rate limits from `req.rateLimit` (set by validatepermissions).
 * Copyright (c) 2026 Discernible IO. All rights reserved.
 */

const { ulid } = require("ulid");
const logger = require("../../services/logger");
const { createLogContext } = logger;
const { sendError } = require("../../services/error-response");

/**
 * In-memory fixed-window counters keyed by subject + path + operation.
 * Suitable for single-process apps; replace/store externally for multi-instance.
 */
const windows = new Map();

function cleanupExpired(now) {
  if (windows.size < 1000) return;
  for (const [key, entry] of windows) {
    if (entry.resetAt <= now) {
      windows.delete(key);
    }
  }
}

function rateLimitSubject(req) {
  if (req.authenticatedRoditId) return String(req.authenticatedRoditId);
  if (req.user) {
    if (req.user.sub) return String(req.user.sub);
    if (req.user.rodit_id) return String(req.user.rodit_id);
  }
  return req.ip || "anonymous";
}

/**
 * Middleware factory that consumes `req.rateLimit` metadata produced by
 * `validatepermissions`. Place after permission validation on protected routes.
 *
 * @param {Object} [options]
 * @param {Map} [options.store] Optional external store (Map-like get/set)
 * @returns {Function} Express middleware
 *
 * @example
 * app.use('/api', authenticate_apicall, validatepermissions, enforceRateLimitFromClaims());
 */
function enforceRateLimitFromClaims(options = {}) {
  const store = options.store || windows;

  return function enforceRateLimitFromClaimsMiddleware(req, res, next) {
    const requestId = req.requestId || ulid();
    const rate = req.rateLimit;

    if (!rate || rate.unlimited === true) {
      return next();
    }

    const limit = Number(rate.value);
    if (!Number.isFinite(limit) || limit <= 0) {
      // Missing / unparsable claim → do not invent a limit
      return next();
    }

    const timeWindowSeconds =
      Number.isFinite(Number(rate.timeWindow)) && Number(rate.timeWindow) > 0
        ? Number(rate.timeWindow)
        : 60;
    const now = Date.now();
    const subject = rateLimitSubject(req);
    const pathKey = rate.path || req.path || "";
    const operation = rate.operation || "";
    const key = `${subject}|${pathKey}|${operation}`;

    cleanupExpired(now);

    let entry = store.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = {
        count: 0,
        resetAt: now + timeWindowSeconds * 1000,
        limit,
      };
    }

    entry.count += 1;
    store.set(key, entry);

    const remaining = Math.max(0, limit - entry.count);
    const resetSeconds = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));

    res.setHeader("X-RateLimit-Limit", String(limit));
    res.setHeader("X-RateLimit-Remaining", String(remaining));
    res.setHeader("X-RateLimit-Reset", String(resetSeconds));

    if (entry.count > limit) {
      const baseContext = createLogContext("EnforceRateLimit", "claimExceeded", {
        requestId,
        subject,
        path: pathKey,
        operation,
        limit,
        count: entry.count,
        timeWindowSeconds,
      });
      logger.warnWithContext("Per-route claim rate limit exceeded", {
        ...baseContext,
        result: "blocked",
      });
      logger.metric &&
        logger.metric("rate_limit_operations", 0, {
          operation: "claim_limit_exceeded",
          path: pathKey,
          result: "blocked",
        });

      return sendError(res, {
        statusCode: 429,
        requestId,
        code: "RATE_LIMIT_EXCEEDED",
        message: "Rate limit exceeded for this permissioned route",
        details: {
          limit,
          timeWindowSeconds,
          operation: operation || undefined,
          path: pathKey || undefined,
        },
      });
    }

    return next();
  };
}

module.exports = enforceRateLimitFromClaims;
module.exports.enforceRateLimitFromClaims = enforceRateLimitFromClaims;
module.exports._windows = windows;
