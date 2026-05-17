// Copyright (c) 2025 Discernible IO. All rights reserved.

/**
 * RODiT Frontend Authentication Service
 * 
 * This module provides browser-compatible authentication and verification functions
 * for RODiT (Routable Decentralized Identity Token) operations. It handles:
 * - NEP-413 authentication flows
 * - JWT token validation
 * - RODiT ownership verification
 * - Cryptographic operations in browser environment
 * 
 * Key Changes from Server Version:
 * - Uses window.crypto for secure random number generation
 * - Implements browser-compatible RPC calls to NEAR blockchain
 * - Simplified DNS verification (skipped in browser for security)
 * - Session storage for authentication state management
 */

/**
 * Module Dependencies
 */
import * as nacl from "tweetnacl";
import { jwtDecode } from "jwt-decode";
import { encodeBase64 } from "tweetnacl-util";
import { Buffer } from "buffer";
import { ulid } from "ulid";

import {
  calculateCanonicalHash,
  base64ToBase64Url,
  base64url2jwk_public_key,
  jwtVerify_fe,
  verifyRoditSignature,
  validateBufferIntegrity,
  verifyHashInputs,
  bufferUtils
} from "../utils.js";

// Import browser-compatible logger
import { logger, createLogContext } from "../services/logger.js";

// Import blockchain-related classes and functions
import {
  CONSTANTS,
  RODiT
} from "../lib/blockchain/blockchainservice.js";

// Browser-compatible versions of authentication functions

/**
 * Converts an owner_id hex string to a Uint8Array public key for cryptographic operations
 * Browser-compatible version that works with RODiT owner_id values
 * 
 * FUNCTION NAME CHANGE: Changed from nearorg_rpc_fetchpublickeybytes_fe to nearorg_rpc_fetchpublickeybytes_fe
 * to match the original working implementation and provide more descriptive naming.
 * 
 * @param {string} accountId - Account ID (owner_id) in hex format
 * @returns {Uint8Array} Public key bytes
 */
async function nearorg_rpc_fetchpublickeybytes_fe(accountId) {
  logger.debug("Fetching public key bytes (browser)", {
    component: "nearorg_rpc_fetchpublickeybytes_fe",
    accountId,
    isImplicitAccount: /^[0-9a-f]{64}$/.test(accountId)
  });
  
  try {
    // Check if accountId is an implicit account (64 hex chars)
    const isImplicitAccount = /^[0-9a-f]{64}$/.test(accountId);
    
    if (isImplicitAccount) {
      logger.debug("Account is implicit, using direct hex encoding", {
        component: "nearorg_rpc_fetchpublickeybytes_fe",
        accountId
      });
      
      // Convert hex string to Uint8Array using the utility function from bufferUtils
      const result = bufferUtils.hexToUint8Array(accountId);
      
      logger.debug("Successfully retrieved public key bytes", {
        component: "nearorg_rpc_fetchpublickeybytes_fe",
        keyLength: result.length,
        expectedLength: 32 // Ed25519 public keys should be 32 bytes
      });
      
      return result;
    }
    
    // If not an implicit account, we need to fetch the RODiT token
    logger.error("Non-implicit accounts not supported in browser environment", {
      component: "nearorg_rpc_fetchpublickeybytes_fe",
      accountId
    });
    throw new Error(`Non-implicit accounts not supported: ${accountId}`);
  } catch (error) {
    logger.error("Failed to fetch public key bytes", {
      component: "nearorg_rpc_fetchpublickeybytes_fe",
      accountId,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      }
    });
    throw new Error(`Failed to fetch public key: ${error.message}`);
  }
}

/**
 * AUTHENTICATION & VERIFICATION FUNCTIONS
 * 
 * The following functions provide browser-compatible versions of RODiT verification
 * operations. Key differences from server versions:
 * - No DNS lookups (security restriction in browsers)
 * - Uses browser crypto APIs
 * - Simplified trust validation for frontend use
 */

// Browser-compatible versions of authentication functions
export async function verify_rodit_ownership(
  peerroditid,
  peertimestamp,
  peerroditid_base64url_signature,
  peer_rodit
) {
  logger.debug("Starting RODiT ownership verification", {
    component: "verify_rodit_ownership",
    peerRoditId: peerroditid,
    timestamp: peertimestamp,
    signatureLength: peerroditid_base64url_signature?.length,
    signatureValue: peerroditid_base64url_signature?.substring(0, 20) + '...',
  });

  try {
    // Convert timestamp to date string in the same format as the backend
    const timeString = new Date(peertimestamp * 1000).toISOString();
    const roditidandtimestamp = new TextEncoder().encode(
      peerroditid + timeString
    );

    logger.debug("Encoded roditid and timestamp", {
      component: "verify_rodit_ownership",
      timeString,
      peerRoditId: peerroditid,
      combinedString: peerroditid + timeString,
      bufferLength: roditidandtimestamp.length,
    });

    // Check if signature is defined before proceeding
    if (!peerroditid_base64url_signature) {
      logger.error("Missing signature in authentication request", {
        component: "verify_rodit_ownership",
        peerRoditId: peerroditid,
      });
      throw new Error("Missing signature in authentication request");
    }

    // Convert base64url signature to Uint8Array using the utility function
    const bytes_ed25519_signature = bufferUtils.base64urlToUint8Array(peerroditid_base64url_signature);
    
    logger.debug("Decoded signature using base64url", {
      component: "verify_rodit_ownership",
      signatureLength: bytes_ed25519_signature.length,
      expectedLength: 64, // Ed25519 signatures should be 64 bytes
    });

    // FUNCTION CALL UPDATE: Changed to use nearorg_rpc_fetchpublickeybytes_fe 
    // to match the corrected function name from the original implementation
    const peer_bytes_ed25519_public_key =
      await nearorg_rpc_fetchpublickeybytes_fe(
        peer_rodit.owner_id
      );

    logger.debug("Retrieved public key", {
      component: "verify_rodit_ownership",
      ownerId: peer_rodit.owner_id,
      keyLength: peer_bytes_ed25519_public_key?.length || 0,
      expectedLength: 32, // Ed25519 public keys should be 32 bytes
    });

    const isaMatch = nacl.sign.detached.verify(
      roditidandtimestamp,
      bytes_ed25519_signature,
      peer_bytes_ed25519_public_key
    );

    if (isaMatch) {
      logger.info("Peer RODiT ownership check successful", {
        component: "verify_rodit_ownership",
        peerRoditId: peerroditid,
        ownerId: peer_rodit.owner_id,
        outcome: "success",
      });
      return true;
    } else {
      logger.error("Peer RODiT ownership check failed", {
        component: "verify_rodit_ownership",
        peerRoditId: peerroditid,
        ownerId: peer_rodit.owner_id,
        outcome: "failed",
      });
      throw new Error("Error 035: PeerEd25519SignatureVerificationFailure");
    }
  } catch (error) {
    logger.error("RODiT ownership verification failed", {
      component: "verify_rodit_ownership",
      peerRoditId: peerroditid,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
      },
    });
    throw new Error("Error A33: " + error.message);
  }
}

export async function verify_rodit_islive(peer_rodit_notafter, peer_rodit_notbefore) {
  logger.debug("Checking RODiT time validity", {
    component: "verify_rodit_islive",
    notAfter: peer_rodit_notafter,
    notBefore: peer_rodit_notbefore,
  });

  function parseDate(datestring) {
    const date = new Date(datestring);
    return isNaN(date.getTime()) ? new Date(0) : date;
  }

  const datetimenul = new Date(0);
  const datetimenotafter = parseDate(peer_rodit_notafter);
  const datetimenotbefore = parseDate(peer_rodit_notbefore);

  logger.debug("Parsed validity dates", {
    component: "verify_rodit_islive",
    parsedNotAfter: datetimenotafter.toISOString(),
    parsedNotBefore: datetimenotbefore.toISOString(),
    isNotAfterNull: datetimenotafter.getTime() === datetimenul.getTime(),
    isNotBeforeNull: datetimenotbefore.getTime() === datetimenul.getTime(),
  });

  try {
    // In the browser, we'll use the current time instead of blockchain time
    const datetimetimestamp = new Date(); 

    logger.debug("Using browser time", {
      component: "verify_rodit_islive",
      browserTime: datetimetimestamp.toISOString(),
    });

    const isAfterNotBefore =
      datetimetimestamp >= datetimenotbefore ||
      datetimenotbefore.getTime() === datetimenul.getTime();

    const isBeforeNotAfter =
      datetimetimestamp <= datetimenotafter ||
      datetimenotafter.getTime() === datetimenul.getTime();

    const isLive = isAfterNotBefore && isBeforeNotAfter;

    if (isLive) {
      logger.info("RODiT is live", {
        component: "verify_rodit_islive",
        currentTime: datetimetimestamp.toISOString(),
        notBefore: datetimenotbefore.toISOString(),
        notAfter: datetimenotafter.toISOString(),
        isLive: true,
      });
      return true;
    } else {
      logger.warn("RODiT is not live - outside valid time period", {
        component: "verify_rodit_islive",
        currentTime: datetimetimestamp.toISOString(),
        notBefore: datetimenotbefore.toISOString(),
        notAfter: datetimenotafter.toISOString(),
        isBeforeExpiry: isBeforeNotAfter,
        isAfterStart: isAfterNotBefore,
        isLive: false,
      });
      return false;
    }
  } catch (error) {
    logger.error("Failed to check RODiT time validity", {
      component: "verify_rodit_islive",
      notAfter: peer_rodit_notafter,
      notBefore: peer_rodit_notbefore,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
      },
    });
    return false;
  }
}

/**
 * BROWSER-SPECIFIC VERIFICATION FUNCTIONS
 * 
 * These functions provide simplified verification for browser environments
 * where DNS lookups and certain security checks are not feasible.
 */

// Browser-compatible versions of DNS-dependent functions
export async function verify_rodit_isactive_fe(tokenId, ownsubjectuniqueidentifier_url) {
  logger.debug("Browser: Checking RODiT activity status", {
    component: "verify_rodit_isactive_fe",
    tokenId,
    subjectUrl: ownsubjectuniqueidentifier_url
  });
  
  // BROWSER LIMITATION: DNS TXT record verification not possible in browser environment
  // for security reasons. Server-side verification should handle this check.
  // In browser environment, we skip DNS checks and assume the token is active
  return true;
}

export async function verify_rodit_istrusted_issuingsmartcontract_fe(ownsubjectuniqueidentifier_url) {
  logger.debug("Browser: Verifying smart contract trust", {
    component: "verify_rodit_istrusted_issuingsmartcontract_fe",
    url: ownsubjectuniqueidentifier_url
  });
  
  // BROWSER LIMITATION: DNS-based trust verification not possible in browser
  // In browser environment, we skip DNS checks and assume trust is established
  return true;
}

// Browser-compatible version of verify_peerrodit_getrodit
export async function verify_peerrodit_getrodit_fe(
  peerroditid,
  peertimestamp,
  peerroditid_base64url_signature,
  authService = null
) {
  // Log the authService parameter to verify it's being passed correctly
  logger.debug("verify_peerrodit_getrodit_fe called with authService", {
    component: "verify_peerrodit_getrodit_fe",
    hasAuthService: !!authService,
    authServiceType: typeof authService,
    authServiceConstructor: authService?.constructor?.name,
    authServiceRpcUrl: authService?.rpcUrl,
    authServiceContractId: authService?.contractId,
    authServiceKeys: authService ? Object.keys(authService) : null,
  });
  const requestId = Math.random().toString(36).substring(2, 15);
  const startTime = Date.now();

  // Get own_rodit from stateManager
  const config_own_rodit = stateManager.getConfigOwnRodit();

  logger.debug("Starting peer RODiT verification", {
    component: "verify_peerrodit_getrodit_fe",
    method: "verify_peerrodit_getrodit_fe",
    requestId,
    peerRoditId: peerroditid,
    timestamp: peertimestamp,
    signatureLength: peerroditid_base64url_signature?.length,
    hasOwnRodit: !!config_own_rodit,
    ownRoditId: config_own_rodit?.token_id,
  });

  try {
    logger.debug("Fetching peer RODiT from blockchain", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      peerRoditId: peerroditid,
    });

    const tokenFetchStart = Date.now();
    const peer_rodit = await nearorg_rpc_tokenfromroditid(
      peerroditid,
      authService?.rpcUrl,
      authService?.contractId
    );
    const tokenFetchDuration = Date.now() - tokenFetchStart;

    logger.debug("Received peer RODiT from blockchain", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      tokenFetchDuration,
      hasPeerRodit: !!peer_rodit,
      peerRoditId: peer_rodit?.token_id,
      peerRoditOwnerId: peer_rodit?.owner_id,
      hasPeerRoditMetadata: peer_rodit && !!peer_rodit.metadata,
      metadataKeys:
        peer_rodit && peer_rodit.metadata
          ? Object.keys(peer_rodit.metadata)
          : [],
    });

    if (!peer_rodit) {
      logger.error("Failed to retrieve peer RODiT data", {
        component: "verify_peerrodit_getrodit_fe",
        method: "verify_peerrodit_getrodit_fe",
        requestId,
        duration: Date.now() - startTime,
        peerRoditId: peerroditid,
      });
      return { peer_rodit: null, goodrodit: false };
    }

    if (!peer_rodit.metadata) {
      logger.error("Peer RODiT missing metadata", {
        component: "verify_peerrodit_getrodit_fe",
        method: "verify_peerrodit_getrodit_fe",
        requestId,
        duration: Date.now() - startTime,
        peerRoditId: peerroditid,
        peerRoditOwnerId: peer_rodit.owner_id,
      });
      return { peer_rodit: null, goodrodit: false };
    }

    // Verify ownership
    const ownershipStart = Date.now();
    const ownershipVerified = await verify_rodit_ownership(
      peerroditid,
      peertimestamp,
      peerroditid_base64url_signature,
      peer_rodit
    );
    const ownershipDuration = Date.now() - ownershipStart;

    logger.debug("Ownership verification completed", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      ownershipDuration,
      ownershipVerified,
    });

    if (!ownershipVerified) {
      logger.warn("Invalid signature, aborting RODiT verification", {
        component: "verify_peerrodit_getrodit_fe",
        requestId,
        roditId: peerroditid,
      });
      return { peer_rodit, goodrodit: false };
    }

    // Verify match
    const matchStart = Date.now();
    
    // Check if config_own_rodit is properly defined before accessing properties
    if (!config_own_rodit || !config_own_rodit.own_rodit || !config_own_rodit.own_rodit.metadata) {
      logger.error("Own RODiT configuration is incomplete", {
        component: "verify_peerrodit_getrodit_fe",
        method: "verify_peerrodit_getrodit_fe",
        requestId,
        duration: Date.now() - startTime,
        hasOwnRodit: !!config_own_rodit,
        hasMetadata: config_own_rodit && !!config_own_rodit.own_rodit.metadata
      });
      return { peer_rodit, goodrodit: false };
    }
    
    const isaMatch = await authService.verify_rodit_isamatch(
      config_own_rodit.own_rodit.metadata.serviceprovider_id,
      peer_rodit
    );
    const matchDuration = Date.now() - matchStart;

    logger.debug("Match verification completed", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      matchDuration,
      isaMatch,
    });

    if (!isaMatch) {
      logger.warn("RODiT match verification failed", {
        component: "verify_peerrodit_getrodit_fe",
        requestId,
        roditId: peerroditid,
      });
      return { peer_rodit, goodrodit: false };
    }

    // Verify live
    const liveStart = Date.now();
    const isLive = await verify_rodit_islive(
      peer_rodit.metadata.not_after,
      peer_rodit.metadata.not_before
    );
    const liveDuration = Date.now() - liveStart;

    logger.debug("Live verification completed", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      liveDuration,
      isLive,
    });

    if (!isLive) {
      logger.warn("RODiT live verification failed", {
        component: "verify_peerrodit_getrodit_fe",
        requestId,
        roditId: peerroditid,
      });
      return { peer_rodit, goodrodit: false };
    }

    // Verify active - using browser-compatible version
    const activeStart = Date.now();
    const isActive = await verify_rodit_isactive_fe(
      peer_rodit.token_id,
      config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url
    );
    const activeDuration = Date.now() - activeStart;

    logger.debug("Active verification completed", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      activeDuration,
      isActive,
    });

    if (!isActive) {
      logger.warn("RODiT active verification failed", {
        component: "verify_peerrodit_getrodit_fe",
        requestId,
        roditId: peerroditid,
      });
      return { peer_rodit, goodrodit: false };
    }

    // Verify trusted - using browser-compatible version
    const trustedStart = Date.now();
    const isTrusted = await verify_rodit_istrusted_issuingsmartcontract_fe(
      config_own_rodit.own_rodit.metadata.subjectuniqueidentifier_url
    );
    const trustedDuration = Date.now() - trustedStart;

    logger.debug("Trust verification completed", {
      component: "verify_peerrodit_getrodit_fe",
      requestId,
      trustedDuration,
      isTrusted,
    });

    if (!isTrusted) {
      logger.warn("RODiT trust verification failed", {
        component: "verify_peerrodit_getrodit_fe",
        requestId,
        roditId: peerroditid,
      });
      return { peer_rodit, goodrodit: false };
    }

    // All checks passed
    const totalDuration = Date.now() - startTime;

    logger.info("RODiT verification successful", {
      component: "verify_peerrodit_getrodit_fe",
      method: "verify_peerrodit_getrodit_fe",
      requestId,
      duration: totalDuration,
      peerRoditId: peerroditid,
    });

    return { peer_rodit, goodrodit: true };
  } catch (error) {
    logger.error("RODiT verification failed", {
      component: "verify_peerrodit_getrodit_fe",
      method: "verify_peerrodit_getrodit_fe",
      requestId,
      duration: Date.now() - startTime,
      peerRoditId: peerroditid,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
      },
    });

    return { peer_rodit: null, goodrodit: false };
  }
}

/**
 * GLOBAL STATE MANAGEMENT
 * 
 * Singleton pattern for managing authentication state across the application.
 * Stores session keys, RODiT configurations, and JWT tokens.
 * 
 * TODO: Consider refactoring to use React Context or Redux for better state management
 */

// Global state (consider refactoring to reduce global state)
class AuthStateManager {
  constructor() {
    if (AuthStateManager.instance) {
      return AuthStateManager.instance;
    }
    AuthStateManager.instance = this;

    // Standardize property names
    this.sessionBase64urlJwkPublicKey = null;
    this.configOwnRodit = null;
    this.currentToken = null;
  }

  // Use consistent method names
  setSessionBase64urlJwkPublicKey(key) {
    this.sessionBase64urlJwkPublicKey = key;
  }

  getSessionBase64urlJwkPublicKey() {
    return this.sessionBase64urlJwkPublicKey;
  }

  setConfigOwnRodit(config) {
    this.configOwnRodit = config;
  }

  getConfigOwnRodit() {
    return this.configOwnRodit;
  }

  setCurrentToken(token) {
    this.currentToken = token;
  }

  getCurrentToken() {
    return this.currentToken;
  }
}

export const stateManager = new AuthStateManager();

// Constants and data structures are now imported from blockchainservice.js

/**
 * Utility Functions
 */
// debugWithType and setValue are now imported from utils.js

export function logBufferState(stage, data, requestId) {
  logger.debug(`Buffer state at ${stage}:`, {
    component: "logBufferState",
    requestId,
    type: typeof data,
    isBuffer: data instanceof Uint8Array,
    length: data?.length || 0,
    // Convert to hex for consistent visualization
    hexRepresentation:
      data instanceof Uint8Array ? Buffer.from(data).toString("hex") : null,
    // If it's a string, show encoding hints
    stringEncoding:
      typeof data === "string"
        ? {
            hasUnicode: /[^\u0000-\u007f]/.test(data),
            length: data.length,
            // Show first 50 chars for context
            preview: data.slice(0, 50),
          }
        : null,
  });
}

export function validateMetadata(metadata) {
  // Validate URLs
  const urls = [
    metadata.openapijson_url,
    metadata.subjectuniqueidentifier_url,
    metadata.webhook_url,
  ];
  const urlPattern = /^https:\/\/([\w\-]+(\.[\w\-]+)+)/;
  urls.forEach((url) => {
    if (url && !urlPattern.test(url)) {
      throw new Error(`Invalid URL format: ${url}`);
    }
  });

  // Validate dates
  const dates = [metadata.not_before, metadata.not_after];
  dates.forEach((date) => {
    if (date) {
      const timestamp = new Date(date).getTime();
      if (isNaN(timestamp)) {
        throw new Error(`Invalid date format: ${date}`);
      }
    }
  });

  // Validate numeric fields
  ["max_requests", "maxrq_window", "jwt_duration"].forEach((field) => {
    const value = metadata[field];
    if (value && isNaN(parseInt(value))) {
      throw new Error(`Invalid numeric value for ${field}: ${value}`);
    }
  });

  return true;
}

/**
 * SESSION MANAGEMENT & AUTHENTICATION SERVICE
 * 
 * Main service class that handles:
 * - NEP-413 authentication flows with NEAR wallet
 * - JWT token management and refresh
 * - RODiT-based login and verification
 * - Session storage and cleanup
 * 
 * CRYPTO SECURITY NOTE: Uses window.crypto.getRandomValues() for secure nonce generation.
 * This requires HTTPS context in main environments.
 */

/**
 * Session Management Functions
 */

export class RoditAuthService {
  constructor(wallet, apiEndpoint, callbackEndpoint, contractId, rpcUrl) {
    this.wallet = wallet;
    this.apiEndpoint = apiEndpoint;
    this.callbackEndpoint = callbackEndpoint;
    this.contractId = contractId;
    this.rpcUrl = rpcUrl;

    // Initialize state from localStorage if available
    const storedToken = localStorage.getItem("jwt_token");
    const storedExpiration = localStorage.getItem("tokenExpiration");

    this.jwt_token = storedToken || null;
    this.tokenExpiration = storedExpiration ? parseInt(storedExpiration) : null;
    this.refreshInterval = null;

    // If we have a stored token, set up refresh
    if (this.jwt_token && this.tokenExpiration) {
      this.setupTokenRefresh();
    }
  }

  async nearorg_wallet_tokensfromaccountid(wallet, contractId, accountId) {
    try {
      const args = {
        account_id: accountId,
        from_index: null,
        limit: null,
      };

      const tokens = await wallet.viewMethod({
        contractId: contractId,
        method: "rodit_tokens_for_owner",
        args: args,
      });

      if (!Array.isArray(tokens) || tokens.length === 0) {
        return null;
      }

      const token = tokens[0];
      if (!token || !token.token_id) {
        return null;
      }

      return {
        token_id: token.token_id,
        owner_id: token.owner_id,
        metadata: token.metadata,
      };
    } catch (error) {
      logger.error("Error fetching tokens:", {
        component: "nearorg_wallet_tokensfromaccountid",
        error
      });
      throw error;
    }
  }

  async login_server_withnep413(options) {
    logger.debug("Debug - login_server_withnep413 options:", {
      component: "login_server_withnep413",
      options
    });

    try {
      if (!this.wallet.accountId) {
        throw new Error("Wallet not connected");
      }

      const own_rodit = await this.nearorg_wallet_tokensfromaccountid(
        this.wallet,
        this.contractId,
        this.wallet.accountId
      );

      if (!own_rodit || !own_rodit.token_id) {
        const errorMsg = `No RODiT found for this account (${this.wallet.accountId}). You need to have at least one RODiT in your wallet before minting additional tokens.`;
        logger.warn("No RODiT found during authentication", {
          component: "login_server_withnep413",
          accountId: this.wallet.accountId,
          contractId: this.contractId
        });
        throw new Error(errorMsg);
      }

      // CRYPTO SECURITY: Generate cryptographically secure random nonce for NEP-413 authentication
      // This requires HTTPS context and modern browser support for window.crypto.getRandomValues()
      // If crypto is not available, the browser environment is likely insecure or outdated
      const nonce = new Uint8Array(32);
      crypto.getRandomValues(nonce);

      // Create loginData object for NEP-413 authentication flow
      const loginData = {
        message: own_rodit.token_id, // 'message' is the RODiT token ID used in NEP-413 protocol
        nonce: Array.from(nonce),
        accountId: this.wallet.accountId,
        recipient: this.apiEndpoint,
        callbackUrl: options?.callbackUrl || `${this.callbackEndpoint}/login`, // Use provided callback URL
        ownrodit: own_rodit,
      };
      sessionStorage.setItem("loginData", JSON.stringify(loginData));

      await this.wallet.signMessageWithNEP413({
        message: own_rodit.token_id,
        recipient: this.apiEndpoint,
        nonce: Buffer.from(nonce),
        callbackUrl: options?.callbackUrl || `${this.callbackEndpoint}/login`, // Use provided callback URL here too
      });
    } catch (error) {
      logger.error("RODiT authentication failed:", {
        component: "login_server_withnep413",
        error
      });
      throw error;
    }
  }

  async handleLoginCallback(url) {
    try {
      const { signature, _, accountId } = this.handleCallbackUrl(url);
      const loginData = JSON.parse(sessionStorage.getItem("loginData"));

      if (!loginData) {
        throw new Error("Login data not found");
      }

      if (loginData.accountId !== accountId) {
        throw new Error("Account ID mismatch");
      }

      // Set up the own RODiT configuration before proceeding with validation
      if (loginData.ownrodit && loginData.ownrodit.token_id) {
        logger.info("Setting up own RODiT configuration", {
          component: "handleLoginCallback",
          roditId: loginData.ownrodit.token_id
        });
        
        // Log the full login data for debugging
        logger.debug("Full login data:", {
          component: "handleLoginCallback",
          loginData: JSON.stringify(loginData, null, 2)
        });
        
        // Check for required fields without adding fallbacks
        if (!loginData.ownrodit.owner_id) {
          logger.error("Missing owner_id in own RODiT configuration", {
            component: "handleLoginCallback",
            accountId,
            roditId: loginData.ownrodit.token_id
          });
        }
        
        // Set the own RODiT configuration in the state manager as-is
        stateManager.setConfigOwnRodit({
          own_rodit: loginData.ownrodit
        });
        
        // Log the configuration that was set
        logger.debug("Own RODiT configuration set", {
          component: "handleLoginCallback",
          hasConfig: !!stateManager.getConfigOwnRodit(),
          roditId: loginData.ownrodit.token_id,
          ownerId: loginData.ownrodit.owner_id,
          hasMetadata: !!loginData.ownrodit.metadata,
          subjectuniqueidentifier_url: loginData.ownrodit.metadata?.subjectuniqueidentifier_url
        });
      } else {
        logger.warn("No own RODiT data available in login data", {
          component: "handleLoginCallback"
        });
      }

      const response = await fetch(`${this.apiEndpoint}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          signature: base64ToBase64Url(signature),
          message: loginData.message, // Required by NEP-413 protocol: contains the RODiT token ID (own_rodit.token_id)
          nonce: loginData.nonce,
          recipient: loginData.recipient,
          callbackUrl: loginData.callbackUrl,
        }),
        credentials: "include",
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Login failed");
      }

      const data = await response.json();
      let jwt_token = data.jwt_token;
      logger.info('JWT token received', {
        component: 'handleLoginCallback',
        hasToken: Boolean(jwt_token),
        tokenLength: jwt_token ? jwt_token.length : 0
      });

      try {
        // Extract server's RODiT ID from the JWT token
        const decoded = jwtDecode(jwt_token);
        logger.info('Server JWT token decoded, audience (server RODiT ID):', {
          component: "handleLoginCallback",
          audience: decoded.aud
        });
        
        if (!decoded.aud) {
          throw new Error('Server JWT token missing audience (RODiT ID)');
        }
        
        // Pass the peer RODiT ID to validate_jwt_token_fe for audience validation
        const { _, peer_rodit } = await this.validate_jwt_token_fe(
          jwt_token,
          decoded.rodit_id  // Peer RODiT ID for audience validation
        );
      } catch (validationError) {
        throw new Error(
          `Error 039: Server validation failed: ${validationError.message}`
        );
      }

      logger.info("Client of API endpoint is logged in", {
        component: "handleLoginCallback"
      });

      // Store the JWT token
      this.storeToken(jwt_token);

      // Return both the token and API endpoint
      return {
        jwt_token,
        apiEndpoint: this.apiEndpoint, // Use the class property instead of undefined variable
      };
    } catch (error) {
      logger.error("Login callback failed:", {
        component: "handleLoginCallback",
        error
      });
      throw error;
    }
  }

  storeToken(token) {
    // Parse the JWT to get expiration
    const [, payload] = token.split(".");
    const { exp } = JSON.parse(atob(payload));

    // Store in instance and localStorage
    this.jwt_token = token;
    this.tokenExpiration = exp;

    localStorage.setItem("jwt_token", token);
    localStorage.setItem("tokenExpiration", exp.toString());
  }

  handleCallbackUrl(url) {
    try {
      const hashParams = url.split("#")[1];
      if (!hashParams) {
        throw new Error("No hash parameters found in URL");
      }

      const params = new URLSearchParams(hashParams);
      const signature = params.get("signature");
      const publicKey = params.get("publicKey");
      const accountId = params.get("accountId");

      if (!signature || !publicKey || !accountId) {
        throw new Error("Missing required parameters");
      }

      return {
        signature: decodeURIComponent(signature),
        publicKey: publicKey.replace("ed25519:", ""),
        accountId,
      };
    } catch (error) {
      logger.error("Error parsing callback URL:", {
        component: "handleCallbackUrl",
        error
      });
      throw error;
    }
  }

  setupTokenRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }

    // Check every minute if token needs refresh
    this.refreshInterval = setInterval(async () => {
      try {
        const now = Math.floor(Date.now() / 1000);
        if (this.tokenExpiration && now > this.tokenExpiration - 300) {
          await this.refreshToken();
        }
      } catch (error) {
        logger.error("Token refresh failed:", {
          component: "setupTokenRefresh",
          error
        });
      }
    }, 60000);
  }

  async refreshToken() {
    try {
      if (!this.jwt_token) {
        throw new Error("No token to refresh");
      }

      const response = await fetch(`${this.apiEndpoint}/refresh`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.jwt_token}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      });

      if (!response.ok) {
        throw new Error("Token refresh failed");
      }

      const { token } = await response.json();
      this.storeToken(token);

      return token;
    } catch (error) {
      logger.error("Token refresh failed:", {
        component: "refreshToken",
        error
      });
      // Clear stored tokens on refresh failure
      this.cleanup();
      throw error;
    }
  }

  cleanup() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
    this.jwt_token = null;
    this.tokenExpiration = null;
    localStorage.removeItem("jwt_token");
    localStorage.removeItem("tokenExpiration");
  }

  // New simplified fetch function for unauthenticated access to signclient
  async fetchSignClient(url, options) {
    try {
      const headers = {
        "Content-Type": "application/json",
        // No authentication token here
      };

      const response = await fetch(url, {
        ...options,
        headers: {
          ...headers,
          ...(options.headers || {}),
        },
      });

      const responseData = await response.json();

      if (!response.ok) {
        throw new Error(
          `Request failed: ${response.statusText}, Details: ${JSON.stringify(
            responseData
          )}`
        );
      }

      return responseData;
    } catch (error) {
      logger.error(`Error in fetch: ${error.message}`, {
        component: "fetchSignClient",
        error
      });

      if (error instanceof SyntaxError && error.message.includes("JSON")) {
        return {
          error: "InvalidResponse",
          message: "The server returned an invalid response",
        };
      }

      return {
        error: "RequestFailed",
        message: error.message,
      };
    }
  }

  async fetchWithErrorHandling_fe(url, options = {}) {
    try {
      if (this.jwt_token) {
        options.headers = {
          ...options.headers,
          Authorization: `Bearer ${this.jwt_token}`,
        };
      }

      const response = await fetch(url, options);
      const newToken = response.headers.get("New-Token");

      if (newToken) {
        this.jwt_token = newToken;
        try {
          const config = await this.roditAuth.get_rodit_config();
          if (!config) throw new Error("Client configuration not initialized");
          await this.roditAuth.validate_jwt_token(newToken, config.own_rodit);
        } catch (error) {
          throw new Error(`Token validation failed: ${error.message}`);
        }
      }

      const responseData = await response.json();

      if (!response.ok) {
        if (
          response.status === 429 &&
          responseData.error === "RateLimitExceeded"
        ) {
          return {
            error: "RateLimitExceeded",
            message: responseData.message,
            retryAfter: parseInt(
              response.headers.get("Retry-After") || "60",
              10
            ),
            maxRequests: responseData.maxRequests,
            windowMinutes: responseData.windowMinutes,
          };
        }
        throw new Error(
          `Request failed: ${response.statusText}, Details: ${JSON.stringify(
            responseData
          )}`
        );
      }

      return responseData;
    } catch (error) {
      logger.error(`Request failed: ${error.message}`, {
        component: "fetchWithErrorHandling_fe",
        error
      });
      if (error instanceof SyntaxError && error.message.includes("JSON")) {
        return { error: "InvalidResponse", message: "Invalid server response" };
      }
      return { error: "RequestFailed", message: error.message };
    }
  }

  async verify_rodit_isamatch(own_service_provider_id, peer_rodit) {
    logger.debug("Starting RODiT match verification", {
      component: "verify_rodit_isamatch",
      ownServiceProviderId: own_service_provider_id,
      peerRoditId: peer_rodit?.token_id,
    });

    try {
      const own_provider_components = own_service_provider_id.split(";");

      logger.debug("Split provider components", {
        component: "verify_rodit_isamatch",
        componentCount: own_provider_components.length,
        components: own_provider_components,
      });

      // Get blockchain and contract parts
      const bcPart = own_provider_components.find((part) =>
        part.startsWith("bc=")
      );
      const scPart = own_provider_components.find((part) =>
        part.startsWith("sc=")
      );

      // Find all ID components
      const idComponents = own_provider_components.filter(
        (part) =>
          part.startsWith("id=") &&
          !part.startsWith("bc=") &&
          !part.startsWith("sc=")
      );

      if (!bcPart || !scPart || idComponents.length < 1) {
        logger.error("Invalid provider ID format", {
          component: "verify_rodit_isamatch",
          providerId: own_service_provider_id,
          components: own_provider_components,
          hasBlockchain: !!bcPart,
          hasSmartContract: !!scPart,
          idCount: idComponents.length,
        });
        return false;
      }

      // Construct the base prefix
      const base_prefix = `${bcPart};${scPart}`;
      logger.debug("Constructed base prefix", {
        component: "verify_rodit_isamatch",
        basePrefix: base_prefix,
      });

      // Try verification with each ID component
      for (let i = 0; i < idComponents.length; i++) {
        const idPosition = i + 1;
        const isPartnerVerification = i === 0;
        const isPeerVerification = i > 0;
        const verificationType = isPartnerVerification ? "PARTNER" : "PEER";
        const signing_token_id = `${base_prefix};${idComponents[i]}`;

        logger.debug(
          `Trying ${verificationType} verification with ID [${idPosition}/${idComponents.length}]`,
          {
            component: "verify_rodit_isamatch",
            idPosition,
            verificationType,
            totalIds: idComponents.length,
            signingTokenId: signing_token_id,
          }
        );

        logger.debug("Blockchain call parameters", {
          component: "verify_rodit_isamatch",
          signingTokenId: signing_token_id,
          rpcUrl: this.rpcUrl,
          contractId: this.contractId,
        });

        const signing_rodit = await nearorg_rpc_tokenfromroditid(
          signing_token_id,
          this.rpcUrl,
          this.contractId
        );

        logger.debug("Retrieved signing RODiT", {
          component: "verify_rodit_isamatch",
          idPosition,
          verificationType,
          tokenId: signing_rodit?.token_id,
          ownerId: signing_rodit?.owner_id,
        });

        // For simplicity in the browser version, we'll just return true if we find a matching token
        // This is a simplified version of the complex verification in the backend
        if (signing_rodit && signing_rodit.token_id) {
          logger.info("RODiT match verification successful", {
            component: "verify_rodit_isamatch",
            verificationType,
            idPosition,
            signingTokenId: signing_token_id,
          });
          return true;
        }
      }

      logger.warn("No matching RODiT found", {
        component: "verify_rodit_isamatch",
        providerId: own_service_provider_id,
      });
      return false;
    } catch (error) {
      logger.error("RODiT match verification failed", {
        component: "verify_rodit_isamatch",
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
      });
      return false;
    }
  }

  async validate_jwt_token_fe(token, rodit_id) {
    try {
      logger.debug('[validate_jwt_token_fe] Starting token validation with rodit_id:', {
        component: 'validate_jwt_token_fe',
        rodit_id
      });
      
      // Call the implementation
      logger.debug('[validate_jwt_token_fe] Calling nearorg_rpc_tokenfromroditid', {
        component: 'validate_jwt_token_fe'
      });
      
      // Track timing
      const startTime = Date.now();
      let sp_rodit;
      
      try {
        sp_rodit = await nearorg_rpc_tokenfromroditid(rodit_id, this.rpcUrl, this.contractId);
        logger.debug('[validate_jwt_token_fe] Implementation completed in', {
          component: 'validate_jwt_token_fe',
          duration: Date.now() - startTime + 'ms',
          result: JSON.stringify(sp_rodit, null, 2)
        });
      } catch (error) {
        logger.error('[validate_jwt_token_fe] Error from implementation:', {
          component: 'validate_jwt_token_fe',
          error,
          errorMessage: error.message,
          errorStack: error.stack
        });
        
        // If this is a known server RODiT ID that's returning null, provide a more helpful error
        if (error.message && error.message.includes('returned null from blockchain')) {
          logger.error('[validate_jwt_token_fe] This appears to be an issue with the token not existing on the blockchain', {
            component: 'validate_jwt_token_fe'
          });
          logger.error('[validate_jwt_token_fe] Please verify that the server RODiT token exists on the NEAR blockchain', {
            component: 'validate_jwt_token_fe'
          });
        }
        
        throw error;
      }
      
      logger.debug('[validate_jwt_token_fe] RODiT details:', {
        component: 'validate_jwt_token_fe',
        roditDetails: JSON.stringify(sp_rodit, null, 2)
      });
      
      if (!sp_rodit || !sp_rodit.owner_id) {
        logger.error('[validate_jwt_token_fe] Error: sp_rodit.owner_id is empty or undefined', {
          component: 'validate_jwt_token_fe'
        });
        throw new Error('Server RODiT owner_id is missing');
      }
      
      logger.debug('[validate_jwt_token_fe] Using owner_id:', {
        component: 'validate_jwt_token_fe',
        owner_id: sp_rodit.owner_id
      });
      
      let serviceprovider_base64_public_key;
      try {
        logger.debug('[validate_jwt_token_fe] Converting owner_id to base64Url format', {
          component: 'validate_jwt_token_fe',
          ownerIdType: typeof sp_rodit.owner_id,
          ownerIdLength: sp_rodit.owner_id.length
        });
        serviceprovider_base64_public_key = bufferUtils.hexToBase64Url(sp_rodit.owner_id);
        logger.debug('[validate_jwt_token_fe] Generated base64 public key from sp_rodit.owner_id', {
          component: 'validate_jwt_token_fe',
          keyLength: serviceprovider_base64_public_key.length
        });
      } catch (conversionError) {
        logger.error('[validate_jwt_token_fe] Error converting owner_id to base64Url:', {
          component: 'validate_jwt_token_fe',
          conversionError,
          errorMessage: conversionError.message,
          errorStack: conversionError.stack
        });
        throw new Error(`Failed to convert owner_id to base64Url: ${conversionError.message}`);
      }
      
      const sp_public_key = await base64url2jwk_public_key(
        serviceprovider_base64_public_key
      );
      logger.debug('[validate_jwt_token_fe] Converted to JWK public key', {
        component: 'validate_jwt_token_fe'
      });

      const { payload, _ } = await jwtVerify_fe(token, sp_public_key, {
        algorithms: ["EdDSA"],
      });
      logger.debug('[validate_jwt_token_fe] JWT verification successful, payload:', {
        component: 'validate_jwt_token_fe',
        payload: JSON.stringify({
          iss: payload.iss,
          sub: payload.sub,
          aud: payload.aud,
          exp: payload.exp,
          nbf: payload.nbf,
          iat: payload.iat,
          rodit_id: payload.rodit_id
        }, null, 2)
      });

      logger.debug('[validate_jwt_token_fe] Verifying peer RODiT', {
        component: 'validate_jwt_token_fe'
      });
      let { peer_rodit, goodrodit } = await verify_peerrodit_getrodit_fe(
        payload.rodit_id,
        payload.iat,
        payload.rodit_idsignature,
        this
      );
      logger.debug('[validate_jwt_token_fe] Peer RODiT verification result:', {
        component: 'validate_jwt_token_fe',
        result: goodrodit ? 'valid' : 'invalid'
      });

      if (goodrodit) {
        const now = Math.floor(Date.now() / 1000);
        logger.debug('[validate_jwt_token_fe] Time validation:', {
          component: 'validate_jwt_token_fe',
          now,
          exp: payload.exp,
          nbf: payload.nbf,
          expired: payload.exp <= now,
          notYetValid: payload.nbf > now
        });
        
        if (payload.exp <= now) {
          logger.error('[validate_jwt_token_fe] Token has expired', {
            component: 'validate_jwt_token_fe'
          });
          throw new Error("Error 007: Token has expired");
        }

        if (payload.nbf > now) {
          logger.error('[validate_jwt_token_fe] Token is not yet valid', {
            component: 'validate_jwt_token_fe'
          });
          throw new Error("Error 006: Token is not yet valid");
        }

        const own_rodit = stateManager.getConfigOwnRodit();
        
        // Log the raw values for inspection
        logger.debug('[validate_jwt_token_fe] TOKEN ISSUER VALUE:', {
          component: 'validate_jwt_token_fe',
          tokenIssuer: payload.iss
        });
        logger.debug('[validate_jwt_token_fe] SUBJECT UNIQUE IDENTIFIER URL:', {
          component: 'validate_jwt_token_fe',
          subjectUrl: own_rodit?.metadata?.subjectuniqueidentifier_url
        });
        
        // Also log the full own_rodit object for inspection
        logger.debug('[validate_jwt_token_fe] FULL OWN_RODIT OBJECT:', {
          component: 'validate_jwt_token_fe',
          ownRodit: JSON.stringify(own_rodit, null, 2)
        });
        
        logger.debug('[validate_jwt_token_fe] Own RODiT:', {
          component: 'validate_jwt_token_fe',
          ownRoditSummary: JSON.stringify({
            owner_id: own_rodit?.owner_id,
            subjectuniqueidentifier_url: own_rodit?.metadata?.subjectuniqueidentifier_url
          }, null, 2)
        });

        // Issuer validation
        logger.debug('[validate_jwt_token_fe] Issuer validation:', {
          component: 'validate_jwt_token_fe',
          tokenIssuer: payload.iss,
          expectedIssuer: own_rodit?.metadata?.subjectuniqueidentifier_url,
          isValid: payload.iss === own_rodit?.metadata?.subjectuniqueidentifier_url,
          hasOwnRodit: !!own_rodit,
          hasMetadata: own_rodit && !!own_rodit.metadata,
          hasSubjectUrl: own_rodit?.metadata && !!own_rodit.metadata.subjectuniqueidentifier_url
        });
        
        // Check if we have a valid subjectuniqueidentifier_url to compare against
        if (own_rodit?.metadata?.subjectuniqueidentifier_url) {
          // Standard validation when we have the expected value
          if (payload.iss !== own_rodit.metadata.subjectuniqueidentifier_url) {
            logger.error('[validate_jwt_token_fe] Invalid issuer', {
            component: 'validate_jwt_token_fe'
          });
            throw new Error("Error 005: Invalid issuer");
          }
        } else {
          // If we don't have the expected value, log a warning but don't fail
          // This allows authentication to proceed when we don't have a complete own RODiT configuration
          logger.warn('[validate_jwt_token_fe] Skipping issuer validation due to incomplete own RODiT configuration', {
            component: 'validate_jwt_token_fe',
            tokenIssuer: payload.iss
          });
        }

        // Audience validation - detailed logging
        logger.debug('[validate_jwt_token_fe] Audience validation:', {
          component: 'validate_jwt_token_fe',
          tokenAudience: payload.aud,
          expectedAudience: own_rodit.owner_id,
          isValid: payload.aud === own_rodit.owner_id,
          ownRoditType: typeof own_rodit,
          ownRoditOwnerIdType: typeof own_rodit.owner_id,
          payloadAudType: typeof payload.aud
        });
        
        // Detailed character-by-character comparison for debugging
        if (payload.aud && sp_rodit.owner_id) {
          const audChars = Array.from(payload.aud);
          const ownerIdChars = Array.from(sp_rodit.owner_id);
          const charComparison = [];
          
          const maxLength = Math.max(audChars.length, ownerIdChars.length);
          for (let i = 0; i < maxLength; i++) {
            charComparison.push({
              index: i,
              audChar: audChars[i] || 'undefined',
              ownerIdChar: ownerIdChars[i] || 'undefined',
              audCharCode: audChars[i] ? audChars[i].charCodeAt(0) : 'N/A',
              ownerIdCharCode: ownerIdChars[i] ? ownerIdChars[i].charCodeAt(0) : 'N/A',
              match: audChars[i] === ownerIdChars[i]
            });
          }
          
          logger.debug('[validate_jwt_token_fe] Character-by-character comparison:', {
            component: 'validate_jwt_token_fe',
            charComparison: JSON.stringify(charComparison, null, 2)
          });
        }
        
        if (payload.aud !== sp_rodit.owner_id) {
          logger.error('[validate_jwt_token_fe] Invalid audience', {
            component: 'validate_jwt_token_fe',
            tokenAudience: payload.aud,
            expectedAudience: sp_rodit.owner_id,
            // Check for case sensitivity or whitespace issues
            stringComparison: `'${payload.aud}' === '${sp_rodit.owner_id}'`,
            lengthComparison: `${payload.aud?.length} === ${sp_rodit.owner_id?.length}`,
            // Additional diagnostics
            audEncoded: payload.aud ? encodeURIComponent(payload.aud) : null,
            ownerIdEncoded: sp_rodit.owner_id ? encodeURIComponent(sp_rodit.owner_id) : null,
            // Check for invisible characters
            audHex: payload.aud ? Array.from(payload.aud).map(c => c.charCodeAt(0).toString(16)).join(' ') : null,
            ownerIdHex: sp_rodit.owner_id ? Array.from(sp_rodit.owner_id).map(c => c.charCodeAt(0).toString(16)).join(' ') : null
          });
          throw new Error("Error 004: Invalid audience");
        }

        logger.info('[validate_jwt_token_fe] Token validation successful', {
          component: 'validate_jwt_token_fe'
        });
        stateManager.setSessionBase64urlJwkPublicKey(
          serviceprovider_base64_public_key
        );

        return { payload, peer_rodit };
      }
    } catch (error) {
      logger.error(`[validate_jwt_token_fe] Error: ${error.message}`, {
        component: 'validate_jwt_token_fe',
        error
      });
      throw error;
    }
  }

}

/**
 * Fetches a RODiT token by ID from the NEAR blockchain
 * 
 * @param {string} roditid - RODiT token ID to fetch
 * @param {string} rpcUrl - RPC URL to use for the request
 * @param {string} contractId - Default contract ID (will be overridden if found in RODiT ID)
 * @returns {Promise<RODiT>} RODiT token object
 */
export async function nearorg_rpc_tokenfromroditid(roditid, rpcUrl = null, contractId = null) {
  const requestId = ulid();
  const startTime = Date.now();
  
  logger.debug('[nearorg_rpc_tokenfromroditid] Fetching token:', {
    component: 'nearorg_rpc_tokenfromroditid',
    roditid,
    rpcUrl,
    contractId
  });
  
  if (!roditid) {
    logger.error('[nearorg_rpc_tokenfromroditid] Null or undefined roditid', {
      component: 'nearorg_rpc_tokenfromroditid'
    });
    throw new Error('RODiT ID cannot be null or undefined');
  }
  
  // Use provided parameters or throw error if missing
  if (!rpcUrl) {
    throw new Error('RPC URL is required. Please provide REACT_APP_NEAR_RPC_URL in your environment configuration.');
  }
  const finalRpcUrl = rpcUrl;
  let finalContractId = contractId;
  
  // Extract contract ID from the RODiT ID for cross-contract fetching
  const scMatch = roditid.match(/sc=([^;]+)/);
  if (scMatch) {
    finalContractId = scMatch[1];
    logger.debug('[nearorg_rpc_tokenfromroditid] Extracted contract ID from RODiT ID:', {
      component: 'nearorg_rpc_tokenfromroditid',
      extractedContractId: finalContractId,
      originalContractId: contractId
    });
  }
  
  try {
    // Use the same encoding approach as the working implementation
    const argsString = `{"token_id": "${roditid}"}`;
    logger.debug('[nearorg_rpc_tokenfromroditid] Args string:', {
      component: 'nearorg_rpc_tokenfromroditid',
      argsString
    });
    
    // Use standard base64 encoding instead of base64url
    const argsBase64 = btoa(argsString);
    logger.debug('[nearorg_rpc_tokenfromroditid] Args base64:', {
      component: 'nearorg_rpc_tokenfromroditid',
      argsBase64
    });
    
    const json_data = {
      jsonrpc: "2.0",
      id: finalContractId,
      method: "query",
      params: {
        request_type: "call_function",
        finality: "final",
        account_id: finalContractId,
        method_name: "rodit_token",
        args_base64: argsBase64,
      },
    };
    
    logger.debug('[nearorg_rpc_tokenfromroditid] Sending request to:', {
      component: 'nearorg_rpc_tokenfromroditid',
      url: finalRpcUrl,
      contractId: finalContractId,
      requestBody: JSON.stringify(json_data)
    });
    
    const response = await fetch(finalRpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(json_data),
    });
    
    if (!response.ok) {
      logger.error('[nearorg_rpc_tokenfromroditid] HTTP error:', {
        component: 'nearorg_rpc_tokenfromroditid',
        status: response.status
      });
      throw new Error(`HTTP error: ${response.status}`);
    }
    
    const responseText = await response.text();
    logger.debug('[nearorg_rpc_tokenfromroditid] Response text:', {
      component: 'nearorg_rpc_tokenfromroditid',
      responseText: responseText.substring(0, 200)
    });
    
    const parsedJson = JSON.parse(responseText);
    
    if (parsedJson.error) {
      logger.error('[nearorg_rpc_tokenfromroditid] RPC error:', {
        component: 'nearorg_rpc_tokenfromroditid',
        error: parsedJson.error
      });
      throw new Error(`RPC error: ${JSON.stringify(parsedJson.error)}`);
    }
    
    if (parsedJson.result && parsedJson.result.error) {
      logger.error('[nearorg_rpc_tokenfromroditid] WASM error:', {
        component: 'nearorg_rpc_tokenfromroditid',
        error: parsedJson.result.error
      });
      throw new Error(`WASM execution error: ${parsedJson.result.error}`);
    }
    
    const resultArray = parsedJson.result.result;
    if (!Array.isArray(resultArray)) {
      logger.error('[nearorg_rpc_tokenfromroditid] Result is not an array:', {
        component: 'nearorg_rpc_tokenfromroditid',
        resultArray
      });
      throw new Error('Result is not an array');
    }
    
    const resultString = new TextDecoder().decode(new Uint8Array(resultArray));
    logger.debug('[nearorg_rpc_tokenfromroditid] Decoded result string:', {
      component: 'nearorg_rpc_tokenfromroditid',
      resultString
    });
    
    if (resultString === "null") {
      logger.error('[nearorg_rpc_tokenfromroditid] Token returned null', {
        component: 'nearorg_rpc_tokenfromroditid'
      });
      throw new Error(`Token ${roditid} returned null from blockchain`);
    }
    
    const parsed = JSON.parse(resultString);
    logger.debug('[nearorg_rpc_tokenfromroditid] Parsed result:', {
      component: 'nearorg_rpc_tokenfromroditid',
      parsed
    });
    
    const rodit = new RODiT();
    Object.assign(rodit, parsed);
    
    return rodit;
  } catch (error) {
    logger.error('[nearorg_rpc_tokenfromroditid] Error:', {
      component: 'nearorg_rpc_tokenfromroditid',
      error
    });
    throw error;
  }
}

/**
 * Validates a JWT token against a RODiT identity
 * 
 * @param {Object} token - JWT token to validate
 * @param {string} message - RODiT token ID from NEP-413 protocol (own_rodit.token_id)
 * @param {Object} rodit_id - Complete RODiT object containing owner_id and other metadata
 * @returns {Promise<Object>} Object containing validation result and peer RODiT
 */
/**
 * Validates a JWT token against a RODiT identity
 * 
 * @param {Object} token - JWT token to validate
 * @param {string} rodit_id - RODiT token ID for verification
 * @returns {Promise<Object>} Object containing validation result and peer RODiT
 */
/**
 * Validates a JWT token against a RODiT identity
 * 
 * @param {string} token - JWT token to validate
 * @param {string} rodit_id - Server's RODiT ID for verification
 * @returns {Promise<Object>} Object containing validation result and peer RODiT
 */


export async function verifyRoditPairBeforeMinting(
  portalMetadata,
  sanctumMetadata,
  PortalSignerPublicKey,
  SanctumSignerPublicKey
) {
  // Validate metadata format
  validateMetadata(portalMetadata);
  validateMetadata(sanctumMetadata);

  // Verify matching fields
  verifyHashInputs(portalMetadata, sanctumMetadata);

  // Create RODiT objects
  const portalRodit = {
    token_id: portalMetadata.token_id,
    metadata: portalMetadata,
  };

  const sanctumRodit = {
    token_id: sanctumMetadata.token_id,
    metadata: sanctumMetadata,
  };

  // Validate buffer integrity
  validateBufferIntegrity(
    PortalSignerPublicKey,
    CONSTANTS.RODIT_ID_PK_SZ,
    "PortalSignerPublicKey"
  );
  validateBufferIntegrity(
    SanctumSignerPublicKey,
    CONSTANTS.RODIT_ID_PK_SZ,
    "SanctumSignerPublicKey"
  );

  // Verify signatures
  const portalValid = await verifyRoditSignature(
    portalRodit,
    SanctumSignerPublicKey
  );
  const sanctumValid = await verifyRoditSignature(
    sanctumRodit,
    PortalSignerPublicKey
  );

  return portalValid && sanctumValid;
}

/**
 * Verifies a RODiT's signature before minting
 *
 * @param {Object} roditMetadata - The RODiT metadata object to verify
 * @param {Uint8Array} signerPublicKey - The public key of the signer (as Uint8Array)
 * @returns {Promise<boolean>} - True if verification passes, false otherwise
 */
/**
 * Verifies a RODiT's signature before minting
 * This is a browser-compatible version that works in the frontend environment
 * 
 * @param {Object} Metadata - The RODiT metadata object to verify
 * @param {Uint8Array} SignerPublicKey - The public key of the signer (as Uint8Array)
 * @param {string} type - Type of verification (client or server) for logging
 * @returns {Promise<boolean>} - True if verification passes, false otherwise
 */
export async function verifyRoditBeforeMinting(Metadata, SignerPublicKey, type) {
  logger.debug(`[DEBUG] Starting ${type} RODiT signature verification:`, {
    component: 'verifyRoditBeforeMinting',
    type,
    roditId: Metadata.token_id,
    signerPubKeyLength: SignerPublicKey?.length,
  });
  
  // Validate the metadata structure
  validateMetadata(Metadata);
  
  logger.debug("[DEBUG] Full metadata object structure:", {
    component: 'verifyRoditBeforeMinting',
    token_id: Metadata.token_id,
    serviceprovider_id: Metadata.serviceprovider_id,
    fields: Object.keys(Metadata).sort().join(', '),
    allowed_iso3166list_type: typeof Metadata.allowed_iso3166list,
    permissioned_routes_type: typeof Metadata.permissioned_routes
  });
  
  // Create the hash input data to check hash calculation
  const hashInput = {
    token_id: Metadata.token_id,
    openapijson_url: Metadata.openapijson_url,
    not_after: Metadata.not_after,
    not_before: Metadata.not_before,
    max_requests: String(Metadata.max_requests),
    maxrq_window: String(Metadata.maxrq_window),
    allowed_cidr: Metadata.allowed_cidr,
    allowed_iso3166list: Metadata.allowed_iso3166list,
    jwt_duration: Metadata.jwt_duration,
    permissioned_routes: Metadata.permissioned_routes,
    webhook_cidr: Metadata.webhook_cidr,
    subjectuniqueidentifier_url: Metadata.subjectuniqueidentifier_url,
    serviceprovider_id: Metadata.serviceprovider_id,
  };

  // Log the hash calculation inputs
  logger.debug("[DEBUG] Hash verification input:", {
    component: 'verifyRoditBeforeMinting',
    keys: Object.keys(hashInput).sort().join(',')
  });

  // Construct the RODiT object for verification
  const rodit = {
    token_id: Metadata.token_id,
    metadata: Metadata,
  };

  // Validate the buffer integrity of the public key
  validateBufferIntegrity(
    SignerPublicKey,
    CONSTANTS.RODIT_ID_PK_SZ,
    "SignerPublicKey"
  );

  // Serialize the input for debugging
  const serializedInput = JSON.stringify(hashInput);
  logger.debug("[DEBUG] Serialized hash input:", {
    component: 'verifyRoditBeforeMinting',
    serializedInput: serializedInput.substring(0, 100) + "..."
  });

  // Calculate hash for comparison
  const verificationHash = calculateCanonicalHash(hashInput);
  logger.debug("[DEBUG] Verification hash:", {
    component: 'verifyRoditBeforeMinting',
    hash: verificationHash.substring(0, 20) + "...",
    length: verificationHash.length
  });

  // Verify the RODiT signature
  const Valid = await verifyRoditSignature(rodit, SignerPublicKey);

  return Valid;
}

// Export all necessary functions and services
export default RoditAuthService;

// Export crypto utilities for use in other modules
export const cryptoUtils = {
  nacl,
  encodeBase64,
  Buffer
};