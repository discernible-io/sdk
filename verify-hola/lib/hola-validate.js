const { validateHexNonce, computeHolaChecksum } = require("./nonce-encoding");

function validateTokenIdFormat(value) {
  return /^[A-Z]{12}$/.test(String(value || ""));
}

function validateHolaMessage(hola) {
  const result = {
    valid: false,
    isSubagentFormat: false,
    recipient: "MUNDO",
    tokenId: null,
    delegateId: null,
    issuerTokenId: null,
    subagentPublicKey: null,
    isoTimestamp: null,
    noncetsHex: null,
    signatureB32: null,
    checksumChar: null,
    reason: null,
    checks: {
      formatValid: false,
      checksumValid: false,
      timestampValid: false,
      noncetsValid: false
    }
  };

  if (!hola || typeof hola !== "string") {
    result.reason = "Missing or invalid hola parameter (must be a string)";
    return result;
  }

  const MAX_HOLA_LENGTH = 512;
  if (hola.length > MAX_HOLA_LENGTH) {
    result.reason = `Hola string exceeds maximum length of ${MAX_HOLA_LENGTH} characters`;
    return result;
  }

  const prefixLiteral = "HOLA/";
  const normalizedHola = hola.toUpperCase();
  if (!normalizedHola.startsWith(prefixLiteral)) {
    result.reason = "Unsupported protocol; expected HOLA prefix";
    return result;
  }

  result.checks.formatValid = true;
  const withoutPrefix = normalizedHola.slice(prefixLiteral.length);
  const recipientSeparatorIndex = withoutPrefix.indexOf("/");
  if (recipientSeparatorIndex === -1) {
    result.reason = "Invalid HOLA format: missing destinatary separator";
    return result;
  }

  const recipientRaw = withoutPrefix.slice(0, recipientSeparatorIndex);
  result.recipient = recipientRaw.length > 0 ? recipientRaw : "MUNDO";
  const afterRecipient = withoutPrefix.slice(recipientSeparatorIndex + 1);

  const lastSeparatorIndex = afterRecipient.lastIndexOf("/");
  if (lastSeparatorIndex === -1) {
    result.reason = "Invalid HOLA format: missing checksum separator";
    return result;
  }

  const checksumCharRaw = afterRecipient.slice(lastSeparatorIndex + 1);
  const beforeChecksum = afterRecipient.slice(0, lastSeparatorIndex);
  if (!checksumCharRaw) {
    result.reason = "Missing checksum";
    return result;
  }
  result.checksumChar = checksumCharRaw.toUpperCase();

  const signatureSeparatorIndex = beforeChecksum.lastIndexOf("/");
  if (signatureSeparatorIndex === -1) {
    result.reason = "Invalid HOLA format: missing signature separator";
    return result;
  }

  result.signatureB32 = beforeChecksum.slice(signatureSeparatorIndex + 1);
  const beforeSignature = beforeChecksum.slice(0, signatureSeparatorIndex);
  if (!result.signatureB32) {
    result.reason = "Missing signature";
    return result;
  }

  const protocolSeparatorIndex = beforeSignature.lastIndexOf("/");
  if (protocolSeparatorIndex === -1) {
    result.reason = "Invalid HOLA format: missing protocol marker separator";
    return result;
  }

  const protocolMarker = beforeSignature.slice(protocolSeparatorIndex + 1);
  if (protocolMarker !== "API.IDENTYCLAW.COM") {
    result.reason = `Invalid protocol marker: expected API.IDENTYCLAW.COM, got ${protocolMarker}`;
    return result;
  }

  const beforeProtocol = beforeSignature.slice(0, protocolSeparatorIndex);
  const noncetsHexSeparatorIndex = beforeProtocol.lastIndexOf("/");
  if (noncetsHexSeparatorIndex === -1) {
    result.reason = "Invalid HOLA format: missing noncets separator";
    return result;
  }

  const noncetsHexRaw = beforeProtocol.slice(noncetsHexSeparatorIndex + 1);
  const tokenAndTimestamp = beforeProtocol.slice(0, noncetsHexSeparatorIndex);
  if (!noncetsHexRaw) {
    result.reason = "Missing noncets";
    return result;
  }

  const noncetsCheck = validateHexNonce(noncetsHexRaw);
  if (!noncetsCheck.valid) {
    result.reason = noncetsCheck.reason;
    return result;
  }

  result.noncetsHex = noncetsCheck.original ?? noncetsCheck.value;
  result.checks.noncetsValid = true;

  const senderFields = tokenAndTimestamp.split("/");
  if (senderFields.length === 2) {
    result.tokenId = senderFields[0];
    result.isoTimestamp = senderFields[1];
  } else if (senderFields.length === 4) {
    result.isSubagentFormat = true;
    result.delegateId = senderFields[0];
    result.issuerTokenId = senderFields[1];
    result.subagentPublicKey = senderFields[2];
    result.isoTimestamp = senderFields[3];
    result.tokenId = result.issuerTokenId;
  } else {
    result.reason = "Invalid HOLA format: expected standard or subagent sender fields";
    return result;
  }

  if (!result.tokenId) {
    result.reason = result.isSubagentFormat ? "Missing issuerTokenId" : "Missing tokenId";
    return result;
  }

  if (!validateTokenIdFormat(result.tokenId)) {
    result.reason = result.isSubagentFormat
      ? "Invalid issuerTokenId: must be exactly 12 letters"
      : "Invalid tokenId: must be exactly 12 letters";
    return result;
  }

  if (!result.isoTimestamp) {
    result.reason = "Missing timestamp";
    return result;
  }

  const tsMs = Date.parse(result.isoTimestamp);
  if (Number.isNaN(tsMs)) {
    result.reason = "Invalid timestamp: must be a valid ISO-8601 string";
    return result;
  }
  result.checks.timestampValid = true;

  const signedMessage = result.isSubagentFormat
    ? `HOLA/${result.recipient}/${result.delegateId}/${result.issuerTokenId}/${result.subagentPublicKey}/${result.isoTimestamp}/${result.noncetsHex}/API.IDENTYCLAW.COM/`
    : `HOLA/${result.recipient}/${result.tokenId}/${result.isoTimestamp}/${result.noncetsHex}/API.IDENTYCLAW.COM/`;
  const canonicalSignedMessage = signedMessage.toUpperCase();
  const checksumPrefix = `${canonicalSignedMessage}${result.signatureB32}/`;
  const expectedChecksum = computeHolaChecksum(checksumPrefix);

  if (result.checksumChar !== expectedChecksum) {
    result.reason = `Invalid checksum: expected ${expectedChecksum}, got ${result.checksumChar}`;
    return result;
  }

  result.checks.checksumValid = true;
  result.valid = true;
  return result;
}

module.exports = { validateHolaMessage };
