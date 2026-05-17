/**
 * Example usage of the performance middleware
 * This file demonstrates how to configure the middleware for your specific API
 */

const performanceMw = require('./performancemw');

// Example 1: Use with default classifier (generic patterns)
// app.use(performanceMw());

// Example 2: Custom classifier for your API structure
const customClassifier = (req) => {
  const path = req.path || req.originalUrl;
  
  // Match your specific API routes
  if (path.startsWith('/api/auth') || path.startsWith('/login') || path.startsWith('/token')) {
    return 'authentication';
  } else if (path.startsWith('/api/blockchain') || path.startsWith('/smart-contract')) {
    return 'blockchain';
  } else if (path.startsWith('/api/rodit')) {
    return 'rodit';
  } else if (path.startsWith('/api/identity')) {
    return 'identity';
  } else if (path.startsWith('/api/user') || path.startsWith('/profile')) {
    return 'user';
  } else if (path.startsWith('/api/mcp')) {
    return 'mcp';
  } else if (path === '/health' || path === '/status') {
    return 'system';
  }
  
  return 'general';
};

// Example 3: Configure with custom classifier and type-specific metrics
const performanceMiddleware = performanceMw({
  classifier: customClassifier,
  metricsByType: {
    'authentication': 'authentication_duration_ms',
    'blockchain': 'blockchain_duration_ms',
    'rodit': 'rodit_operation_duration_ms',
    'identity': 'identity_operation_duration_ms',
    'mcp': 'mcp_operation_duration_ms'
  }
});

// app.use(performanceMiddleware);

// Example 4: Using the exported default classifier
// const { defaultClassifier } = require('./performancemw');
// const myClassifier = (req) => {
//   // Add custom logic first
//   if (req.path.startsWith('/api/custom')) return 'custom';
//   // Fall back to default
//   return defaultClassifier(req);
// };

module.exports = performanceMiddleware;
