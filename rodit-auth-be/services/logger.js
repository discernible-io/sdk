/**
 * Logging service
 * Copyright (c) 2026 Discernible IO. All rights reserved.
 */

const winston = require("winston");
const config = require('./configsdk');

const SERVICE_NAME = config.get("SERVICE_NAME");

// Custom format to standardize and enhance logs for monitoring
const monitoringFormat = winston.format.combine(
  // Convert errors to serializable objects with proper stack traces
  winston.format((info) => {
    // Handle Error objects
    if (info.error instanceof Error) {
      info.error = {
        message: info.error.message,
        stack: info.error.stack,
        name: info.error.name
      };
    }
    // Standardize log level names to uppercase
    if (info.level) {
      info.level = info.level.toUpperCase();
    }
    // Add standard fields if not present
    info.service_name = SERVICE_NAME;
    info.context = info.context || {};
    // Add hostname for better filtering
    info.hostname = require('os').hostname();
    return info;
  })(),
  // Convert to JSON with proper spacing
  winston.format.json()
);

// Create the default logger: stdout JSON only (no file transports)
let currentLogger = winston.createLogger({
  level: config.get("LOG_LEVEL", "debug"), // Configurable via config with fallback
  format: monitoringFormat,
  defaultMeta: { service_name: SERVICE_NAME },
  levels: winston.config.npm.levels,
  transports: [
    new winston.transports.Console({
      format: monitoringFormat
    })
  ],
});

// Add helper methods for consistent context logging
function attachHelpers(baseLogger) {
  baseLogger.logWithContext = (level, message, context = {}, error = null) => {
    baseLogger.log({
      level,
      message,
      context,
      ...(error && { error })
    });
  };

  ['error', 'warn', 'info', 'debug'].forEach(level => {
    baseLogger[`${level}WithContext`] = (message, context = {}, error = null) => {
      baseLogger.logWithContext(level, message, context, error);
    };
    
    // Add conditional logging helpers to avoid verbose if-statements
    baseLogger[`${level}If`] = (condition, message, context = {}, error = null) => {
      if (condition) {
        if (level === 'error') {
          baseLogger[level](message, context, error);
        } else {
          baseLogger[level](message, context);
        }
      }
    };
    
  });

  // Add metric function for monitoring style metrics
  baseLogger.metric = (name, value, labels = {}) => {
    baseLogger.debug(`METRIC: ${name}=${value}`, {
      context: {
        metric_name: name,
        metric_value: value,
        metric_labels: labels,
        metric_type: 'gauge'
      }
    });
  };

  // Add helper to log error and metrics in a standardized way to avoid duplication
  baseLogger.logErrorWithMetrics = (message, context = {}, error = null, metricName = 'error_count', metricLabels = {}) => {
    baseLogger.errorWithContext(message, context, error);
    baseLogger.metric(metricName, 1, {
      error_type: error?.name || "Unknown",
      error_message: error?.message?.substring(0, 100) || "Unknown",
      ...metricLabels
    });
  };

  /**
   * Creates a standardized context object for logging
   */
  baseLogger.createLogContext = function(component, event, data = {}, error = null) {
    return {
      component,
      event,
      ...(error && { error: typeof error === 'string' ? error : error.message }),
      ...data
    };
  };


  return baseLogger;
}

currentLogger = attachHelpers(currentLogger);

// Allow consumers to inject their own logger that implements { error, warn, info, debug, log }
function setLogger(customLogger) {
  if (!customLogger || typeof customLogger !== 'object') {
    throw new Error('setLogger(customLogger) requires a logger object');
  }
  const required = ['error', 'warn', 'info', 'debug', 'log'];
  const missing = required.filter(m => typeof customLogger[m] !== 'function');
  if (missing.length) {
    throw new Error(`Injected logger is missing methods: ${missing.join(', ')}`);
  }
  const previous = currentLogger;
  currentLogger = attachHelpers(customLogger);
  return previous;
}

// Export a stable facade that delegates to the current logger
const FORWARDED_METHODS = [
  'error',
  'warn',
  'info',
  'debug',
  'logWithContext',
  'errorWithContext',
  'warnWithContext',
  'infoWithContext',
  'debugWithContext',
  'metric',
  'logErrorWithMetrics',
  'createLogContext',
];

const facade = {
  setLogger,
  get SERVICE_NAME() { return SERVICE_NAME; },
};

FORWARDED_METHODS.forEach((methodName) => {
  facade[methodName] = (...args) => currentLogger[methodName](...args);
});

module.exports = facade;