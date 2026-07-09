const { parseUserSelectedDn } = require("./parse-dn");

const DEFAULT_BASE = "https://api.identyclaw.com";

async function verifyHola(hola, { baseUrl = DEFAULT_BASE, jwt, expectedRecipient, includeProfile = false } = {}) {
  const body = { hola };
  if (expectedRecipient) body.expectedRecipient = expectedRecipient;
  if (includeProfile) body.includeProfile = true;

  const headers = { "Content-Type": "application/json", Accept: "application/json" };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;

  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/api/identity/verify`, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });

  const result = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message =
      result?.error?.message || result?.message || `HTTP ${res.status}`;
    throw new Error(message);
  }
  return result;
}

async function resolveDid(tokenId, { baseUrl = DEFAULT_BASE } = {}) {
  const normalized = String(tokenId || "").trim().toLowerCase();
  if (!/^[a-z]{12}$/.test(normalized)) {
    throw new Error("tokenId must be 12 lowercase letters");
  }

  const res = await fetch(
    `${baseUrl.replace(/\/$/, "")}/api/mcp/resource/did:resolve:${normalized}`,
    { headers: { Accept: "application/json" } }
  );

  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(payload?.error?.message || `DID resolve HTTP ${res.status}`);
  }

  const content = payload?.content ?? payload;
  return typeof content === "string" ? JSON.parse(content) : content;
}

function extractProfileFromDid(didDocument) {
  const metadataService = (didDocument?.service || []).find(
    (s) => s.type === "RoditTokenMetadata"
  );
  const metadata = metadataService?.serviceEndpoint?.metadata || {};
  const rawDn = metadata.userselected_dn || null;
  const parsed = parseUserSelectedDn(rawDn);

  return {
    tokenId: metadataService?.serviceEndpoint?.tokenId || didDocument?.id?.split(":").pop() || null,
    ownerAccountId: metadataService?.serviceEndpoint?.ownerAccountId || didDocument?.controller || null,
    did: didDocument?.id || null,
    displayName: parsed.displayName,
    creature: parsed.creature,
    contactUris: parsed.contactUris,
    webhookUrl: metadata.webhook_url || parsed.webhookUrl || null,
    dn: parsed
  };
}

async function buildHolaReport(hola, options = {}) {
  const {
    baseUrl = DEFAULT_BASE,
    jwt,
    expectedRecipient,
    canonicalPeerId,
    includeProfile = true
  } = options;

  const verifyResult = await verifyHola(hola, {
    baseUrl,
    jwt,
    expectedRecipient,
    includeProfile
  });

  const report = {
    verified: Boolean(verifyResult.verified),
    peerTokenId: verifyResult.peerTokenId || null,
    destinatary: verifyResult.destinatary || null,
    checks: verifyResult.checks || {},
    failureReasons: verifyResult.failureReasons || [],
    failureDetails: verifyResult.failureDetails || [],
    warnings: verifyResult.warnings || [],
    requestId: verifyResult.requestId || null,
    impersonationGuard: null,
    profile: null
  };

  if (canonicalPeerId && report.verified) {
    const expected = String(canonicalPeerId).trim().toLowerCase();
    const matched = report.peerTokenId === expected;
    report.impersonationGuard = {
      expectedTokenId: expected,
      matched,
      passed: matched
    };
    if (!matched) {
      report.verified = false;
      report.failureReasons = [...(report.failureReasons || []), "impersonation_guard_failed"];
    }
  }

  if (includeProfile && report.peerTokenId && !verifyResult.profile) {
    try {
      const didDocument = await resolveDid(report.peerTokenId, { baseUrl });
      report.profile = extractProfileFromDid(didDocument);
    } catch (error) {
      report.profile = { error: error.message };
    }
  }

  if (verifyResult.profile) {
    report.profile = { ...report.profile, ...verifyResult.profile };
  }

  return report;
}

module.exports = {
  DEFAULT_BASE,
  verifyHola,
  resolveDid,
  extractProfileFromDid,
  buildHolaReport
};
