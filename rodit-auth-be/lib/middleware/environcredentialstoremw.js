/**
 * Environment-based credential storage system
 * Mirrors filecredentialstoremw.js but reads credentials JSON from an environment variable
 *
 * Copyright (c) 2026 Discernible IO. All rights reserved.
 */

const { ulid } = require("ulid");
const config = require("../../services/configsdk");
const logger = require("../../services/logger");
const { createLogContext, logErrorWithMetrics } = logger;
const { validateAndExtractCredentials } = require("../../services/utils");

class EnvManager {
  constructor() {
    this.envVarName = "NEAR_CREDENTIALS_JSON_B64";
    this.initialized = false;
    this.credentials = {};
  }

  async initialize(source = {}) {
    const context = createLogContext("EnvCredentialStore", "initialize", {
      requestId: ulid(),
      hasSourceValue: source && (typeof source.envCredentialsJson !== "undefined"),
    });

    logger.debugWithContext("Initializing env credential store", context);

    if (this.initialized) {
      logger.debugWithContext("Env credential store already initialized", context);
      return this;
    }

    try {
      // Prefer explicit source override, then config/env
      let rawValue =
        typeof source.envCredentialsJson !== "undefined"
          ? source.envCredentialsJson
          : config.get(this.envVarName, process.env[this.envVarName] || null);

      if (rawValue == null || (typeof rawValue === "string" && rawValue.trim() === "")) {
        // Keep empty object credentials; downstream may handle missing credentials
        logger.infoWithContext("Credentials env var is empty or not set", {
          ...context,
          envVarName: this.envVarName,
        });
        this.credentials = {};
        this.initialized = true;
        return this;
      }

      let parsed;
      if (typeof rawValue === "string") {
        // Primary: base64-encoded JSON
        const decoded = Buffer.from(rawValue, "base64").toString("utf8");
        parsed = JSON.parse(decoded);
      } else {
        parsed = rawValue;
      }

      const validated = validateAndExtractCredentials(parsed, logger);
      this.credentials = validated || {};
      this.initialized = true;

      logger.debugWithContext("Env credential store initialized successfully", {
        ...context,
        hasCredentials: !!this.credentials && Object.keys(this.credentials).length > 0,
      });

      return this;
    } catch (error) {
      logErrorWithMetrics(
        "Failed to initialize env credential store",
        {
          ...context,
          error: error.message,
          stack: error.stack,
          envVarName: this.envVarName,
        },
        error,
        error.name === "SyntaxError" ? "env_parse_error" : "env_credential_init_error",
        { error_type: error.name === "SyntaxError" ? "parse_failure" : "init_failure" }
      );
      throw error;
    }
  }

  async getCredentials(_source) {
    const context = createLogContext("EnvCredentialStore", "getCredentials", {
      requestId: ulid(),
      envVarName: this.envVarName,
    });
    const startTime = Date.now();

    try {
      // Use cached if available
      if (this.credentials && Object.keys(this.credentials).length > 0) {
        logger.debugWithContext("Using cached env credentials", context);
        return this.credentials;
      }

      // Fallback to reading again if not cached yet
      let rawValue = config.get(this.envVarName, process.env[this.envVarName] || null);
      if (rawValue == null || (typeof rawValue === "string" && rawValue.trim() === "")) {
        logger.infoWithContext("No credentials found in environment", context);
        return {};
      }

      let parsed;
      if (typeof rawValue === "string") {
        try {
          const decoded = Buffer.from(rawValue, "base64").toString("utf8");
          parsed = JSON.parse(decoded);
        } catch (e) {
          logger.infoWithContext("Falling back to raw JSON parsing for credentials env var", {
            ...context,
            envVarName: this.envVarName,
            reason: "b64_decode_or_parse_failed",
          });
          parsed = JSON.parse(rawValue);
        }
      } else {
        parsed = rawValue;
      }
      const result = validateAndExtractCredentials(parsed, logger);

      logger.debugWithContext("Successfully processed env credentials", {
        ...context,
        hasRequiredFields: true,
        duration: Date.now() - startTime,
      });

      // Cache for future calls
      this.credentials = result || {};
      return result;
    } catch (error) {
      logErrorWithMetrics(
        "Error retrieving credentials from environment",
        {
          ...context,
          duration: Date.now() - startTime,
          errorDetails: error.message,
          errorType: error.name,
        },
        error,
        error.name === "SyntaxError" ? "env_parse_error" : "env_credential_retrieval_error",
        { error_type: error.name === "SyntaxError" ? "parse_failure" : "retrieval_failure" }
      );
      throw error;
    }
  }

  // No-op to maintain interface compatibility with vaultcredentialstoremw.js
  async setupSecretStorageTokenRenewal() {
    const context = createLogContext("EnvCredentialStore", "setupSecretStorageTokenRenewal", {
      requestId: ulid(),
    });
    logger.debugWithContext(
      "Skipping secret storage token renewal setup (not applicable for env-based credentials)",
      context
    );
    return Promise.resolve();
  }
}

// Create and export a singleton instance
const envManager = new EnvManager();

module.exports = {
  initializeCredentialStore: (source) => envManager.initialize(source),
  setupSecretStorageTokenRenewal: () => envManager.setupSecretStorageTokenRenewal(),
  getCredentials: (source) => envManager.getCredentials(source),
  vault: null,
  // For testing purposes
  _envManager: envManager,
};
