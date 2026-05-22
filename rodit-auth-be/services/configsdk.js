/**
 * Configuration management
 * Copyright (c) 2025 Discernible IO. All rights reserved.
 */

/*
 * SDK Config Wrapper with Fallback Defaults
 *
 * This module wraps the 'config' package to provide safe accessors that
 * gracefully fall back to baked-in defaults when config keys are missing.
 *
 * Exclusions: Vault keys (VAULT_*) and METHOD_PERMISSION_MAP are intentionally
 * NOT included in fallback defaults.
 */


// Attempt to load the 'config' package if present in the host app
let nodeConfig = null;
try {
  // Using require directly so consumer apps can bring their own 'config'
  // eslint-disable-next-line import/no-extraneous-dependencies
  nodeConfig = require("config");
} catch (_) {
  nodeConfig = null;
}

// Deep utilities (no external deps)
function deepGet(obj, keyPath) {
  if (!obj || !keyPath) return undefined;
  const parts = keyPath.split(".");
  let cur = obj;
  for (const p of parts) {
    if (cur && Object.prototype.hasOwnProperty.call(cur, p)) {
      cur = cur[p];
    } else {
      return undefined;
    }
  }
  return cur;
}

function isPlainObject(val) {
  return val && typeof val === "object" && !Array.isArray(val);
}

function deepMerge(target, source) {
  const out = Array.isArray(target) ? [...target] : { ...(target || {}) };
  if (isPlainObject(source)) {
    for (const [k, v] of Object.entries(source)) {
      if (isPlainObject(v)) {
        out[k] = deepMerge(out[k] || {}, v);
      } else if (Array.isArray(v)) {
        out[k] = Array.isArray(out[k]) ? [...out[k], ...v] : [...v];
      } else {
        out[k] = v;
      }
    }
  }
  return out;
}

function candidateState(rawValue) {
  if (rawValue === undefined || rawValue === null) return "missing";
  if (typeof rawValue === "string" && rawValue.trim() === "") return "missing";
  return "present";
}

function parseCandidateForType(rawValue, expectedType) {
  const state = candidateState(rawValue);
  if (state === "missing") {
    return { state: "missing", value: undefined };
  }

  if (!expectedType) {
    return { state: "valid", value: rawValue };
  }

  if (expectedType === "boolean") {
    if (typeof rawValue === "boolean") {
      return { state: "valid", value: rawValue };
    }
    if (typeof rawValue === "string") {
      const lower = rawValue.trim().toLowerCase();
      if (lower === "true") return { state: "valid", value: true };
      if (lower === "false") return { state: "valid", value: false };
    }
    return {
      state: "malformed",
      reason: "boolean values must be string 'true' or 'false'"
    };
  }

  if (expectedType === "number") {
    if (typeof rawValue === "number" && Number.isFinite(rawValue)) {
      return { state: "valid", value: rawValue };
    }
    if (typeof rawValue === "string") {
      const trimmed = rawValue.trim();
      if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
        const parsed = Number(trimmed);
        if (Number.isFinite(parsed)) {
          return { state: "valid", value: parsed };
        }
      }
    }
    return { state: "malformed", reason: "number value is not parseable" };
  }

  if (expectedType === "string") {
    if (typeof rawValue === "string") {
      return { state: "valid", value: rawValue };
    }
    return { state: "malformed", reason: "string value expected" };
  }

  return { state: "valid", value: rawValue };
}

function inferExpectedType(pathStr, fallbackValue, defaultValue) {
  const ruleType = VALIDATION_RULES?.[pathStr]?.type;
  if (ruleType) return ruleType;
  if (fallbackValue !== undefined && fallbackValue !== null) return typeof fallbackValue;
  if (defaultValue !== undefined && defaultValue !== null) return typeof defaultValue;
  return undefined;
}

function getResolved(pathStr, defaultValue) {
  const envVarName = pathStr.toUpperCase().replace(/\./g, "_");
  const hasEnvKey = Object.prototype.hasOwnProperty.call(process.env, envVarName);
  const envRaw = hasEnvKey ? process.env[envVarName] : undefined;

  let hostRaw;
  let hasHostValue = false;
  if (nodeConfig) {
    try {
      hostRaw = nodeConfig.get(pathStr);
      hasHostValue = true;
    } catch (_) {
      hasHostValue = false;
    }
  }

  const fallbackValue = deepGet(FALLBACK_DEFAULTS, pathStr);
  const hasFallback = fallbackValue !== undefined;
  const hasDefaultArg = defaultValue !== undefined;
  const expectedType = inferExpectedType(pathStr, fallbackValue, defaultValue);

  if (hasEnvKey) {
    const envParsed = parseCandidateForType(envRaw, expectedType);
    if (envParsed.state === "valid") {
      return {
        value: envParsed.value,
        source: "environment",
        reason: "environment value provided"
      };
    }
    if (hasFallback) {
      return {
        value: fallbackValue,
        source: "default",
        reason: `default, environment value ${envParsed.state}`
      };
    }
    if (hasDefaultArg) {
      return {
        value: defaultValue,
        source: "default",
        reason: `default, environment value ${envParsed.state}`
      };
    }
  }

  if (hasHostValue) {
    const hostParsed = parseCandidateForType(hostRaw, expectedType);
    if (hostParsed.state === "valid") {
      return {
        value: hostParsed.value,
        source: "default.json",
        reason: "default.json value provided"
      };
    }
    if (hasFallback) {
      return {
        value: fallbackValue,
        source: "default",
        reason: `default, default.json value ${hostParsed.state}`
      };
    }
    if (hasDefaultArg) {
      return {
        value: defaultValue,
        source: "default",
        reason: `default, default.json value ${hostParsed.state}`
      };
    }
  }

  if (hasFallback) {
    return {
      value: fallbackValue,
      source: "default",
      reason: "default, no environment or default.json value"
    };
  }

  if (hasDefaultArg) {
    return {
      value: defaultValue,
      source: "default",
      reason: "default argument used"
    };
  }

  const err = new Error(`Configuration property '${pathStr}' is not defined`);
  err.code = "CONFIG_PROPERTY_MISSING";
  throw err;
}

// Baked-in fallback defaults sourced from config/default.json (excluding Vault and METHOD_PERMISSION_MAP)
const FALLBACK_DEFAULTS = {
  API_VERSION: "0.0.0",
  // Credential source strategy.
  // Options:
  // - "env": read credentials from environment-backed sources
  // - "file": read credentials from filesystem-backed sources
  // - "vault": read credentials from vault-backed sources (when available)
  RODIT_NEAR_CREDENTIALS_SOURCE: "env",
  SECURITY_OPTIONS: {
    LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY: "0.80",
    THRESHOLD_VALIDATION_TYPE: "0.10",
    DURATIONRAMP: "0.85",
    // RODiT flow initiator behavior.
    // Options:
    // - "SERVER-INITIATED": server starts the flow
    // - "CLIENT-INITIATED": client starts the flow
    SERVERORCLIENT: "SERVER-INITIATED",
    // Login error behavior.
    // Options:
    // - true: hide detailed login failure reasons from clients
    // - false: return detailed login failure reasons to clients
    SILENT_LOGIN_FAILURES: false,
    // Session validation strictness.
    // Options:
    // - true: allow relaxed validation checks
    // - false: enforce strict validation checks
    RELAXED_SESSION_VALIDATION: true,
    // Session middleware secret used for signing session data.
    // Options:
    // - any non-empty string (recommended: long, random secret on main)
    SESSION_SECRET: "HMAC-session-secret-is-not-set",
    // Webhook outbound TLS verification.
    // Options:
    // - true: skip TLS certificate verification (for controlled/self-signed setups)
    // - false: enforce normal TLS certificate verification
    WEBHOOK_TLS_SKIP_VERIFY: false,
    // Inbound webhook signature verification bypass.
    // Options:
    // - true: bypass signature verification (test/debug only)
    // - false: require signature verification
    BYPASS_WEBHOOK_VERIFICATION: false,
    LOGIN_MODE: "partner", // Options: "partner" (default), "promiscuous", "p2p"
    // Default JWT lifetime (seconds) when peer/own RODiT metadata jwt_duration is missing or invalid.
    FALLBACK_JWT_DURATION: 3600,
    // Upper bound on JWT exp (seconds from iat) when peer RODiT not_after is unbounded
    // (1970-01-01 / unix 0). Metadata jwt_duration may be shorter; this value is only a cap.
    JWT_MAX_DURATION_SECONDS_RODIT_UNBOUNDED: 86400,
  },
  // Default to env-based credential store; host apps can override with RODIT_NEAR_CREDENTIALS_SOURCE env
  credentials: {
    filePath: "./.near-credentials/credentials-not-set.json"
  },
  API_DEFAULT_OPTIONS: {
    ISO639: "es",
    ISO3166: "ES",
    ISO15924: "215",
    TIMESTAMP_MAX_AGE: 300,
    TIMEOPTIONS: {
      tzname: "Europe/Madrid",
      tzoffset: "+01:00",
      datetimeformat: "2023-04-15T14:30:00-05:00",
    },
  },
  NEAR_RPC_URL: "https://rpc.mainnet.fastnear.com",
  NEAR_CONTRACT_ID: "rodit-org.near",
  SERVICE_NAME: "service-name-not-set",
  // Runtime environment.
  // Options: "main", "development", "test"
  NODE_ENV: "development",
  // Logging verbosity.
  // Options: "error", "warn", "info", "debug", "trace"
  LOG_LEVEL: "info",
  LOKI_TLS_SKIP_VERIFY: false,
  // Default login endpoint path used by login_server flow.
  LOGIN_RODIT_PATH: "/api/login",
  SIGNPORTAL_API_URL: "https://signportal.api-not-set.example.com",
  // Session storage configuration
  // Options:
  // - "memory": standalone in-memory SDK store
  // - "express" / "express-session": express-session MemoryStore adapter
  SESSION_STORAGE_TYPE: "memory",
  // Session cleanup configuration
  SESSION_CLEANUP_INTERVAL: 500000, // Milliseconds
  SESSION_TOKEN_RETENTION_PERIOD: 5000000,  // Seconds
  NEAR_RPC_CACHE_TTL: 5000, // Milliseconds
  // Session validation cache TTL (milliseconds) - trades security for performance
  // Lower values = more secure but more storage lookups
  // Higher values = faster but longer window after logout where token may still work
  // Set to 0 to disable caching (always check session state)
  SESSION_VALIDATION_CACHE_TTL: 5000, // 5 seconds default
  WEBHOOK_TEST_ENABLED: false,
  // Default empty permission map so consumers can opt-into permissions as needed
  METHOD_PERMISSION_MAP: {},
};

function has(pathStr) {
  try {
    return getResolved(pathStr).value !== undefined;
  } catch (_) {
    return false;
  }
}

/**
 * Get configuration value with fallback support
 * @param {string} pathStr - Configuration key path (e.g., 'API_DEFAULT_OPTIONS.LOG_DIR')
 * @param {*} defaultValue - Optional default value if key is missing
 * @returns {*} Configuration value
 */
function get(pathStr, defaultValue) {
  return getResolved(pathStr, defaultValue).value;
}

function getAllMerged() {
  // Returns a merged view: node config (if any) overlaid onto fallbacks
  let merged = { ...FALLBACK_DEFAULTS };
  if (nodeConfig && typeof nodeConfig.util?.toObject === "function") {
    try {
      const asObject = nodeConfig.util.toObject();
      merged = deepMerge(FALLBACK_DEFAULTS, asObject);
    } catch (_) {}
  }
  return merged;
}

/**
 * Validation rules for critical configuration
 */
const VALIDATION_RULES = {
  'NEAR_RPC_URL': {
    required: true,
    type: 'string',
    validate: (value, logger) => {
      if (!value.startsWith('http://') && !value.startsWith('https://')) {
        return 'NEAR_RPC_URL must be a valid HTTP/HTTPS URL';
      }
      // Warn if using public endpoint
      if (value.includes('rpc.mainnet.near.org')) {
        logger && logger.warn('Using public NEAR RPC endpoint; expect rate limiting', {
          rpcUrl: value,
          recommendation: 'Use a dedicated RPC provider for main deployments'
        });
      }
      return null;
    }
  },
  'SECURITY_OPTIONS.LOGIN_MODE': {
    required: true,
    type: 'string',
    validate: (value) => {
      const validModes = ['partner', 'promiscuous', 'p2p'];
      if (!validModes.includes(value)) {
        return `LOGIN_MODE must be one of: ${validModes.join(', ')}`;
      }
      return null;
    }
  },
  'LOG_LEVEL': {
    required: false,
    type: 'string',
    validate: (value) => {
      const validLevels = ['error', 'warn', 'info', 'debug'];
      if (value && !validLevels.includes(value)) {
        return `LOG_LEVEL must be one of: ${validLevels.join(', ')}`;
      }
      return null;
    }
  },
  'SECURITY_OPTIONS.WEBHOOK_TLS_SKIP_VERIFY': {
    required: false,
    type: 'boolean',
    validate: () => null
  },
  'SECURITY_OPTIONS.BYPASS_WEBHOOK_VERIFICATION': {
    required: false,
    type: 'boolean',
    validate: () => null
  },
  'SECURITY_OPTIONS.SESSION_SECRET': {
    required: false,
    type: 'string',
    validate: (value) => {
      if (!value || value.length === 0) {
        return 'SECURITY_OPTIONS.SESSION_SECRET cannot be empty when provided';
      }
      return null;
    }
  },
  'SECURITY_OPTIONS.FALLBACK_JWT_DURATION': {
    required: false,
    type: 'number',
    validate: (value) => {
      if (value != null && (value < 60 || value > 86400 * 7)) {
        return 'SECURITY_OPTIONS.FALLBACK_JWT_DURATION should be between 60 and 604800 seconds (7 days)';
      }
      return null;
    }
  },
  'NEAR_RPC_TIMEOUT': {
    required: false,
    type: 'number',
    validate: (value) => {
      if (value && (value < 1000 || value > 60000)) {
        return 'NEAR_RPC_TIMEOUT should be between 1000-60000ms';
      }
      return null;
    }
  },
  'NEAR_CONTRACT_ID': {
    required: true,
    type: 'string',
    validate: (value) => {
      if (!value || value.length === 0) {
        return 'NEAR_CONTRACT_ID cannot be empty';
      }
      return null;
    }
  }
};

/**
 * Validate configuration against defined rules
 * @param {Object} logger - Optional logger instance for warnings
 * @returns {boolean} True if validation passes
 * @throws {Error} If validation fails
 */
function validate(logger) {
  const errors = [];
  const warnings = [];

  if (logger) {
    if (typeof logger.infoWithContext === "function") {
      logger.infoWithContext("Validating configuration", {
        component: "ConfigSDK",
        operation: "config.validate"
      });
    } else {
      logger.info("Validating configuration");
    }
  }

  for (const [key, rules] of Object.entries(VALIDATION_RULES)) {
    let value;
    try {
      value = get(key);
    } catch (err) {
      if (rules.required) {
        errors.push(`Missing required config: ${key}`);
      }
      continue;
    }

    // Type check
    if (rules.type && typeof value !== rules.type) {
      errors.push(`${key} must be of type ${rules.type}, got ${typeof value}`);
      continue;
    }

    // Custom validation
    if (rules.validate) {
      const validationError = rules.validate(value, logger);
      if (validationError) {
        errors.push(`${key}: ${validationError}`);
      }
    }

    if (logger) {
      if (typeof logger.debugWithContext === "function") {
        logger.debugWithContext("Configuration key validated", {
          component: "ConfigSDK",
          operation: "config.validate",
          key,
          value
        });
      } else {
        logger.debug(`${key}: ${value}`);
      }
    }
  }

  if (errors.length > 0) {
    if (logger) {
      if (typeof logger.errorWithContext === "function") {
        logger.errorWithContext("Configuration validation failed", {
          component: "ConfigSDK",
          operation: "config.validate",
          errors
        });
      } else {
        logger.error("Configuration validation failed", { errors });
      }
    }
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }

  if (warnings.length > 0) {
    if (logger) {
      if (typeof logger.warnWithContext === "function") {
        logger.warnWithContext("Configuration warnings", {
          component: "ConfigSDK",
          operation: "config.validate",
          warnings
        });
      } else {
        logger.warn("Configuration warnings", { warnings });
      }
    }
  }

  if (logger) {
    if (typeof logger.infoWithContext === "function") {
      logger.infoWithContext("Configuration validation passed", {
        component: "ConfigSDK",
        operation: "config.validate"
      });
    } else {
      logger.info("Configuration validation passed");
    }
  }
  return true;
}

/**
 * Default JWT/session duration (seconds) when RODiT metadata jwt_duration is absent or invalid.
 *
 * @returns {number}
 */
function getDefaultJwtDurationSeconds() {
  const parsed = parseInt(get("SECURITY_OPTIONS.FALLBACK_JWT_DURATION", "3600"), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 3600;
}

module.exports = {
  has,
  get,
  getResolved,
  getAllMerged,
  getDefaultJwtDurationSeconds,
  validate,
  FALLBACK_DEFAULTS,
  VALIDATION_RULES,
};
