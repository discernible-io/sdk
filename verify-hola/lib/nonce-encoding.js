const HOLA_CHECKSUM_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ";
const HOLA_CHECKSUM_MOD = HOLA_CHECKSUM_ALPHABET.length;

function validateHexNonce(nonce) {
  if (typeof nonce !== "string") {
    return { valid: false, value: null, reason: "nonce must be a string" };
  }
  const upper = nonce.toUpperCase();
  if (upper.length === 0) {
    return { valid: false, value: null, reason: "nonce must not be empty" };
  }
  if (!/^[0-9A-F]+$/.test(upper)) {
    return { valid: false, value: null, reason: "nonce must contain only [0-9A-F] characters" };
  }
  return { valid: true, value: upper, original: nonce, reason: null };
}

function computeHolaChecksum(prefix) {
  let sum = 0;
  for (let i = 0; i < prefix.length; i += 1) {
    sum += prefix.charCodeAt(i);
  }
  return HOLA_CHECKSUM_ALPHABET[sum % HOLA_CHECKSUM_MOD];
}

module.exports = { validateHexNonce, computeHolaChecksum };
