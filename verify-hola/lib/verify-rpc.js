const base32 = require("hi-base32");
const nacl = require("tweetnacl");
const { validateHolaMessage } = require("./hola-validate");
const { parseUserSelectedDn } = require("./parse-dn");

const DEFAULT_MAX_HOLA_AGE_MS = 5 * 60 * 1000;
const nonceReplayCache = new Map();

function decodeBase32ToBytes(value) {
  const raw = String(value).toUpperCase().replace(/=+$/g, "");
  if (!/^[A-Z2-7]+$/.test(raw)) {
    throw new Error("Invalid base32 input");
  }
  const padded = raw.padEnd(Math.ceil(raw.length / 8) * 8, "=");
  return new Uint8Array(base32.decode.asBytes(padded));
}

function isRoditTokenExpired(token) {
  const notAfter = token?.metadata?.not_after;
  if (!notAfter || String(notAfter).startsWith("1970-01-01")) {
    return false;
  }
  const notAfterMs = Date.parse(String(notAfter));
  if (Number.isNaN(notAfterMs)) {
    return false;
  }
  return Date.now() > notAfterMs;
}

function cleanupExpiredVerifyNonceEntries() {
  const now = Date.now();
  for (const [key, entry] of nonceReplayCache.entries()) {
    if (!entry || entry.expiresAtMs <= now) {
      nonceReplayCache.delete(key);
    }
  }
}

function buildProfileFromToken(token, tokenId) {
  const metadata = token?.metadata || {};
  const parsed = parseUserSelectedDn(metadata.userselected_dn || "");
  return {
    tokenId: String(tokenId).toLowerCase(),
    did: `did:rodit:${String(tokenId).toLowerCase()}`,
    ownerAccountId: token?.owner_id || null,
    displayName: parsed.displayName,
    creature: parsed.creature,
    contactUris: parsed.contactUris,
    webhookUrl: metadata.webhook_url || parsed.webhookUrl || null
  };
}

function ensureNearEnv({ nearRpcUrl, nearContractId } = {}) {
  if (nearRpcUrl) process.env.NEAR_RPC_URL = nearRpcUrl;
  if (nearContractId) process.env.NEAR_CONTRACT_ID = nearContractId;

  const rpc = process.env.NEAR_RPC_URL;
  const contract = process.env.NEAR_CONTRACT_ID;
  if (!rpc) {
    throw new Error("NEAR_RPC_URL is required for --rpc verification (e.g. https://rpc.mainnet.fastnear.com)");
  }
  if (!contract) {
    throw new Error("NEAR_CONTRACT_ID is required for --rpc verification (e.g. genaaaa-identyclaw-com.near)");
  }
  return { rpc, contract };
}

async function verifyHolaViaRpc(hola, options = {}) {
  const {
    maxAgeMs = DEFAULT_MAX_HOLA_AGE_MS,
    nearRpcUrl,
    nearContractId
  } = options;

  ensureNearEnv({ nearRpcUrl, nearContractId });

  const validation = validateHolaMessage(hola);
  if (!validation.valid) {
    return {
      verified: false,
      verifyPath: "near-rpc",
      peerTokenId: validation.tokenId ? String(validation.tokenId).toLowerCase() : null,
      destinatary: validation.recipient,
      checks: {
        tokenExists: false,
        tokenActive: false,
        signatureValid: false,
        timestampFresh: false,
        checksumValid: Boolean(validation.checks?.checksumValid),
        nonceReplaySafe: true
      },
      failureReasons: ["hola_format_invalid"],
      failureDetails: [{ reasonCode: "hola_format_invalid", message: validation.reason }],
      profile: null
    };
  }

  const lookupTokenId = String(validation.tokenId).toLowerCase();
  const checks = {
    tokenExists: false,
    tokenActive: false,
    signatureValid: false,
    timestampFresh: false,
    checksumValid: true,
    nonceReplaySafe: true
  };
  const failureReasons = [];

  const tsMs = Date.parse(validation.isoTimestamp);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const tsSeconds = Math.floor(tsMs / 1000);
  const ageSeconds = nowSeconds - tsSeconds;
  const maxAgeSeconds = Math.floor(maxAgeMs / 1000);
  if (ageSeconds >= 0 && ageSeconds <= maxAgeSeconds) {
    checks.timestampFresh = true;
  } else {
    failureReasons.push("timestamp_stale_or_future");
  }

  cleanupExpiredVerifyNonceEntries();
  const nonceReplayKey = `${lookupTokenId}|${String(validation.noncetsHex).toUpperCase()}`;
  if (nonceReplayCache.has(nonceReplayKey)) {
    checks.nonceReplaySafe = false;
    failureReasons.push("nonce_replay");
  }

  const { blockchainService } = require("@rodit/rodit-auth-be");
  let token = null;
  let profile = null;

  try {
    token = await blockchainService.nearorg_rpc_tokenfromroditid(lookupTokenId);
    if (token && token.token_id) {
      checks.tokenExists = true;
      checks.tokenActive = !isRoditTokenExpired(token);
      profile = buildProfileFromToken(token, lookupTokenId);
      if (!checks.tokenActive) {
        failureReasons.push("token_expired");
      }
    } else {
      failureReasons.push("token_missing");
    }

    if (token && token.owner_id) {
      let publicKeyBytes;
      if (validation.isSubagentFormat) {
        try {
          publicKeyBytes = decodeBase32ToBytes(validation.subagentPublicKey);
          if (publicKeyBytes.length !== 32) {
            failureReasons.push("subagent_public_key_invalid_length");
            publicKeyBytes = null;
          }
        } catch {
          failureReasons.push("subagent_public_key_decode_failed");
          publicKeyBytes = null;
        }
      } else {
        publicKeyBytes = await blockchainService.nearorg_rpc_fetchpublickeybytes(token.owner_id);
      }

      if (publicKeyBytes && publicKeyBytes.length === 32) {
        const message = validation.isSubagentFormat
          ? `HOLA/${validation.recipient}/${validation.delegateId}/${validation.issuerTokenId}/${validation.subagentPublicKey}/${validation.isoTimestamp}/${validation.noncetsHex}/API.IDENTYCLAW.COM/`
          : `HOLA/${validation.recipient}/${validation.tokenId}/${validation.isoTimestamp}/${validation.noncetsHex}/API.IDENTYCLAW.COM/`;
        const canonicalMessage = message.toUpperCase();
        const messageBytes = new TextEncoder().encode(canonicalMessage);
        const signatureBytes = decodeBase32ToBytes(validation.signatureB32);
        if (nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes)) {
          checks.signatureValid = true;
        } else {
          failureReasons.push("signature_invalid");
        }
      } else if (!validation.isSubagentFormat) {
        failureReasons.push("public_key_unavailable");
      }
    }
  } catch (error) {
    failureReasons.push("public_key_error");
    return {
      verified: false,
      verifyPath: "near-rpc",
      peerTokenId: lookupTokenId,
      destinatary: validation.recipient,
      checks,
      failureReasons,
      failureDetails: [{ reasonCode: "public_key_error", message: error.message }],
      profile
    };
  }

  const verified =
    checks.tokenExists &&
    checks.tokenActive &&
    checks.timestampFresh &&
    checks.nonceReplaySafe &&
    checks.signatureValid &&
    checks.checksumValid;

  if (verified) {
    nonceReplayCache.set(nonceReplayKey, {
      expiresAtMs: tsMs + maxAgeMs,
      firstSeenAtMs: Date.now()
    });
  }

  const response = {
    verified,
    verifyPath: "near-rpc",
    nearRpcUrl: process.env.NEAR_RPC_URL,
    nearContractId: process.env.NEAR_CONTRACT_ID,
    peerTokenId: lookupTokenId,
    destinatary: validation.recipient,
    checks,
    failureReasons,
    profile
  };

  if (validation.isSubagentFormat) {
    response.isSubagentFormat = true;
    response.delegateId = validation.delegateId;
    response.issuerTokenId = validation.issuerTokenId;
    response.subagentNote =
      "Subagent delegation requires POST /api/isauthorizedsigner — not checked on --rpc path";
  }

  return response;
}

async function buildHolaReportViaRpc(hola, options = {}) {
  const { canonicalPeerId, ...rpcOptions } = options;
  const report = await verifyHolaViaRpc(hola, rpcOptions);

  if (canonicalPeerId && report.verified) {
    const expected = String(canonicalPeerId).trim().toLowerCase();
    const matched = report.peerTokenId === expected;
    report.impersonationGuard = { expectedTokenId: expected, matched, passed: matched };
    if (!matched) {
      report.verified = false;
      report.failureReasons = [...(report.failureReasons || []), "impersonation_guard_failed"];
    }
  }

  return report;
}

module.exports = {
  verifyHolaViaRpc,
  buildHolaReportViaRpc,
  ensureNearEnv
};
