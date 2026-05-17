/**
 * RODiT Authentication SDK - Main Entry Point
 * Copyright (c) 2025 Discernible IO. All rights reserved.
 *
 * This is the main entry point for the @rodit/rodit-auth-fe npm package.
 * It exports all the necessary functions and classes for RODiT authentication
 * in both Node.js and browser environments.
 *
 * Utils are re-exported directly (no eager require) so consumers importing only
 * logger or other subsets do not necessarily bundle all of utils.js.
 */

// Logger — main-environment oriented (env levels, context sanitization); see services/logger.js
export {
  logger,
  createLogContext,
  sanitizeLogContext,
  formatLogMessage,
} from './services/logger.js';

// Import and re-export frontend functions
export {
  RoditAuthService,
  verify_rodit_ownership,
  verify_rodit_islive,
  verify_rodit_isamatch,
  verify_rodit_isactive_fe,
  verify_rodit_istrusted_issuingsmartcontract_fe,
  verify_peerrodit_getrodit_fe,
  stateManager,
  logBufferState,
  validateMetadata,
  verifyRoditBeforeMinting,
  verifyRoditPairBeforeMinting
} from './frontend/rodit_fe.js';

// Re-export utils (CommonJS) as named exports from the public SDK surface
export {
  calculateCanonicalHash,
  canonicalizeObject,
  debugWithType,
  verifyFeeSignatureBeforeMinting,
  base64ToBase64Url,
  base64url2jwk_public_key,
  jwtVerify_fe,
  verifyRoditSignature,
  validateBufferIntegrity,
  verifyHashInputs,
  bufferUtils,
  validateAndSetUrl,
  validateAndSetDate,
  validateAndSetJson,
  validateAndSetSignature,
  validateSignatureFormat,
  validatePublicKeyFormat,
} from './utils.js';

// Export blockchain services
export {
  CONSTANTS,
  RODiT
} from './lib/blockchain/blockchainservice.js';
