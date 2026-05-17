/**
 * Performance monitoring middleware
 * Provides request tracing and performance metrics collection
 * Copyright (c) 2025 Discernible IO. All rights reserved.
 */

const { ulid } = require("ulid");
const logger = require("../../services/logger");
const performanceService = require('../../services/performanceservice');

/**
 * Default request classifier - can be overridden by consumer
 * 
 * @param {Object} req - Express request object
 * @returns {string} Request classification
 */
function defaultClassifier(req) {
  const path = req.path || req.originalUrl;
  
  // Generic classification based on common patterns
  if (path.startsWith('/auth') || path.includes('/login') || path.includes('/token')) {
    return 'authentication';
  } else if (path.includes('/health') || path.includes('/status') || path.includes('/metrics')) {
    return 'system';
  }
  
  return 'general';
}

/**
 * Middleware factory for monitoring request performance
 * This middleware should be applied before the logging middleware
 * to ensure request IDs and timing are properly set up.
 * 
 * @param {Object} options - Configuration options
 * @param {Function} options.classifier - Custom function to classify requests (optional)
 * @param {Object} options.metricsByType - Map of request types to metric names (optional)
 * @returns {Function} Express middleware function
 */
const performanceMw = (options = {}) => {
  const { 
    classifier = defaultClassifier,
    metricsByType = {}
  } = options;
  
  return (req, res, next) => {
  // Generate request ID if not already present and make it available for other middleware
  req.requestId = req.requestId || ulid();
  
  // Record the start time and make it available for other middleware
  req.startTime = Date.now();
  
  // Log function call for performance monitoring
  logger.infoWithContext("Performance middleware engaged", {
    component: "PerformanceMiddleware",
    method: req.method,
    path: req.originalUrl,
    requestId: req.requestId,
    clientIP: req.ip,
    result: 'call',
    reason: 'Performance monitoring started'
  });

  // Record the request in the performance monitoring service
  performanceService.recordRequest(req);
  
  // Start a trace for this request
  const traceId = performanceService.startTrace('HTTP Request', {
    method: req.method,
    path: req.originalUrl,
    requestId: req.requestId,
    userAgent: req.get('User-Agent'),
    clientIP: req.ip
  });
  
  // Store the trace ID on the request object for other middleware to use
  req.traceId = traceId;
  
  // Capture the original end function
  const originalEnd = res.end;
  
  // Override the end function
  res.end = function(chunk, encoding) {
    // Call the original end function
    originalEnd.call(this, chunk, encoding);
    
    // Calculate request duration
    const duration = Date.now() - req.startTime;
    
    // Store duration for other middleware to use
    req.duration = duration;
    
    // Classify request only when needed for metrics (performance optimization)
    const requestType = classifier(req);
    req.requestType = requestType;
    
    // Record standard metrics using the logger.metric function
    const result = (res.statusCode >= 200 && res.statusCode < 300) ? 'success' : 'failure';
    const reason = (result === 'success') ? 'Request completed successfully' : (res.statusMessage || 'Request failed');
    logger.metric('http_request_duration_ms', duration, {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      request_type: requestType,
      result,
      reason
    });
    
    // Record error metrics if applicable
    if (res.statusCode >= 400) {
      logger.metric('http_errors_total', 1, {
        method: req.method,
        status: res.statusCode,
        error_type: res.statusCode >= 500 ? 'server_error' : 'client_error',
        request_type: requestType,
        result: 'failure',
        reason: res.statusMessage || 'Request failed'
      });
    }
    
    // Complete the trace with request results
    performanceService.completeTrace(traceId, {
      statusCode: res.statusCode,
      success: res.statusCode < 400,
      error: res.statusCode >= 400 ? (res.statusMessage || 'HTTP Error') : null,
      duration,
      responseSize: res._contentLength || 0
    });
    
    // Record specialized metrics based on the request type (if configured)
    const metricName = metricsByType[requestType];
    if (metricName) {
      logger.metric(metricName, duration, {
        result,
        reason,
        method: req.method,
        request_type: requestType
      });
    }
    
    // Always log errors regardless of load level
    if (res.statusCode >= 500) {
      logger.error("Server error occurred", {
        component: "API",
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        duration,
        requestId: req.requestId,
        traceId
      });
    } else if (res.statusCode >= 400) {
      logger.warn("Client error occurred", {
        component: "API",
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        duration,
        requestId: req.requestId,
        traceId
      });
    }
  };
  
    next();
  };
};

module.exports = performanceMw;
module.exports.defaultClassifier = defaultClassifier;
