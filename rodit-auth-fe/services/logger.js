/**
 * Browser-Compatible Logger Service for RODiT SDK
 * Copyright (c) 2026 Discernible IO. All rights reserved.
 *
 * Main-environment oriented: log levels, context sanitization, no sensitive fields in output.
 *
 * Environment (browser: set via build, e.g. Parcel):
 * - REACT_APP_LOG_LEVEL — silent | error | warn | info | debug
 *   Default: warn on main (NODE_ENV=main), debug in development.
 * - REACT_APP_DIAGNOSTIC_MODE — "1" to include stack traces on errors on main
 *   (omit in normal main to limit reverse-engineering surface).
 * - REACT_APP_LOG_METRICS — "1" to emit logger.metric on main (default: off on main).
 */

// Generate unique IDs for browser environment
function generateId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

function getEnv() {
  return typeof process !== "undefined" && process.env ? process.env : {};
}

const SEVERITY_RANK = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

/** Keys matching this pattern are replaced with [redacted] (nested objects recurse). */
const SENSITIVE_KEY_RE =
  /(password|secret|token|jwt|signature|privatekey|authorization|cookie|apikey|mnemonic|bearer|refresh_token|access_token|fee_signature|serviceprovider_signature|public_key|fee_data_json)/i;

/**
 * Returns a structure safe to attach to logs (redacts known sensitive field names).
 * @param {any} obj
 * @param {number} depth
 * @returns {any}
 */
export function sanitizeLogContext(obj, depth = 0) {
  if (depth > 8) return "[max-depth]";
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "bigint") return obj.toString();
  if (obj instanceof Error) {
    return {
      name: obj.name,
      message: String(obj.message).slice(0, 500),
    };
  }
  if (typeof obj !== "object") return obj;
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeLogContext(item, depth + 1));
  }
  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEY_RE.test(key)) {
      out[key] = "[redacted]";
      continue;
    }
    if (value !== null && typeof value === "object") {
      out[key] = sanitizeLogContext(value, depth + 1);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function parseExplicitLevel(value) {
  if (!value || typeof value !== "string") return null;
  const s = value.trim().toLowerCase();
  if (s === "silent") return -1;
  if (s === "error") return 0;
  if (s === "warn") return 1;
  if (s === "info") return 2;
  if (s === "debug") return 3;
  return null;
}

/**
 * Max severity rank to emit (inclusive). -1 = silent.
 */
function getMaxSeverityRank() {
  const env = getEnv();
  const explicit = env.REACT_APP_LOG_LEVEL || env.LOG_LEVEL;
  const parsed = parseExplicitLevel(explicit);
  if (parsed !== null) return parsed;
  const isMain = env.NODE_ENV === "main";
  return isMain ? SEVERITY_RANK.warn : SEVERITY_RANK.debug;
}

function shouldEmit(severity) {
  const max = getMaxSeverityRank();
  if (max < 0) return false;
  const rank = SEVERITY_RANK[severity];
  if (rank === undefined) return false;
  return rank <= max;
}

function includeStacksInOutput() {
  const env = getEnv();
  if (env.REACT_APP_DIAGNOSTIC_MODE === "1") return true;
  return env.NODE_ENV !== "main";
}

function metricsEnabled() {
  const env = getEnv();
  if (env.REACT_APP_LOG_METRICS === "1") return true;
  return env.NODE_ENV !== "main";
}

function scrubContext(context, severity) {
  if (context === undefined || context === null) return {};
  const base =
    typeof context === "object" && !Array.isArray(context)
      ? sanitizeLogContext(context)
      : { value: context };

  if (severity === "error" && typeof context === "object" && context !== null) {
    if (context.stack && typeof context.stack === "string") {
      if (includeStacksInOutput()) {
        base.stack = String(context.stack).slice(0, 4000);
      }
    }
  }
  if (!includeStacksInOutput() && base.stack) {
    delete base.stack;
  }
  return base;
}

/**
 * Creates a standardized log context object
 * @param {string} component - The component/class name
 * @param {string} method - The method name
 * @param {Object} additionalContext - Additional context data
 * @returns {Object} Structured context object
 */
export function createLogContext(component, method, additionalContext = {}) {
  return {
    component,
    method,
    timestamp: new Date().toISOString(),
    requestId: additionalContext.requestId || generateId(),
    ...additionalContext,
  };
}

/**
 * Formats log messages with consistent structure
 * @param {string} level - Log level (DEBUG, INFO, WARN, ERROR)
 * @param {string} message - Log message
 * @param {Object} context - Context object
 * @returns {string} Formatted log message
 */
export function formatLogMessage(level, message, context = {}) {
  const timestamp = new Date().toISOString();
  const component = context.component || "SDK";
  const method = context.method || "";
  const requestId = context.requestId || "";

  let prefix = `[${level}] ${timestamp}`;
  if (component) prefix += ` [${component}`;
  if (method) prefix += `.${method}`;
  if (component) prefix += "]";
  if (requestId) prefix += ` (${String(requestId).substring(0, 8)})`;

  return `${prefix} ${message}`;
}

function emitConsole(severity, formattedMessage, scrubbed) {
  const payload =
    scrubbed && typeof scrubbed === "object" && Object.keys(scrubbed).length > 0
      ? scrubbed
      : undefined;
  if (severity === "error") {
    if (payload !== undefined) console.error(formattedMessage, payload);
    else console.error(formattedMessage);
  } else if (severity === "warn") {
    if (payload !== undefined) console.warn(formattedMessage, payload);
    else console.warn(formattedMessage);
  } else if (severity === "info") {
    if (payload !== undefined) console.info(formattedMessage, payload);
    else console.info(formattedMessage);
  } else {
    if (payload !== undefined) console.debug(formattedMessage, payload);
    else console.debug(formattedMessage);
  }
}

export const logger = {
  debug: (message, context = {}) => {
    if (!shouldEmit("debug")) return;
    const scrubbed = scrubContext(context, "debug");
    if (typeof message === "string" && typeof context === "object") {
      emitConsole("debug", formatLogMessage("DEBUG", message, scrubbed), scrubbed);
    } else {
      emitConsole("debug", formatLogMessage("DEBUG", String(message)), scrubbed);
    }
  },

  info: (message, context = {}) => {
    if (!shouldEmit("info")) return;
    const scrubbed = scrubContext(context, "info");
    if (typeof message === "string" && typeof context === "object") {
      emitConsole("info", formatLogMessage("INFO", message, scrubbed), scrubbed);
    } else {
      emitConsole("info", formatLogMessage("INFO", String(message)), scrubbed);
    }
  },

  warn: (message, context = {}) => {
    if (!shouldEmit("warn")) return;
    const scrubbed = scrubContext(context, "warn");
    if (typeof message === "string" && typeof context === "object") {
      emitConsole("warn", formatLogMessage("WARN", message, scrubbed), scrubbed);
    } else {
      emitConsole("warn", formatLogMessage("WARN", String(message)), scrubbed);
    }
  },

  error: (message, context = {}) => {
    if (!shouldEmit("error")) return;
    const scrubbed = scrubContext(context, "error");
    if (typeof message === "string" && typeof context === "object") {
      emitConsole("error", formatLogMessage("ERROR", message, scrubbed), scrubbed);
    } else {
      emitConsole("error", formatLogMessage("ERROR", String(message)), scrubbed);
    }
  },

  child: (baseContext = {}) => {
    return {
      debug: (message, context = {}) =>
        logger.debug(message, { ...baseContext, ...context }),
      info: (message, context = {}) =>
        logger.info(message, { ...baseContext, ...context }),
      warn: (message, context = {}) =>
        logger.warn(message, { ...baseContext, ...context }),
      error: (message, context = {}) =>
        logger.error(message, { ...baseContext, ...context }),
    };
  },

  infoWithContext: (message, context = {}) => {
    logger.info(message, context);
  },

  errorWithContext: (message, context = {}) => {
    logger.error(message, context);
  },

  metric: (name, value, tags = {}) => {
    if (!metricsEnabled()) return;
    if (!shouldEmit("info")) return;
    const context = sanitizeLogContext({
      component: "Metrics",
      metricName: name,
      metricValue: value,
      tags,
    });
    emitConsole(
      "info",
      formatLogMessage("METRIC", `${name}: ${value}`, context),
      context
    );
  },

  time: (label, context = {}) => {
    const startTime = Date.now();
    return {
      end: () => {
        const duration = Date.now() - startTime;
        logger.debug(`${label} completed`, {
          ...context,
          duration: `${duration}ms`,
          performance: true,
        });
        return duration;
      },
    };
  },
};

export default logger;
