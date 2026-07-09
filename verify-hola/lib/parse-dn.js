/**
 * Parse userselected_dn comma-separated key=value pairs (public subset for verify report).
 */
function splitDistinguishedName(rawDn) {
  const parts = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < rawDn.length; i += 1) {
    const ch = rawDn[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
      continue;
    }
    if (ch === "," && !inQuotes) {
      if (current.trim()) parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function parseDnComponent(part) {
  const eq = part.indexOf("=");
  if (eq <= 0) return null;
  const attribute = part.slice(0, eq).trim();
  let value = part.slice(eq + 1).trim();
  if (value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1);
  }
  return { attribute, value };
}

function parseUserSelectedDn(rawDn) {
  if (typeof rawDn !== "string" || rawDn.trim().length === 0) {
    return {
      displayName: null,
      creature: null,
      contactUris: [],
      webhookUrl: null,
      raw: rawDn || null
    };
  }

  const components = splitDistinguishedName(rawDn.trim())
    .map(parseDnComponent)
    .filter(Boolean);

  const attributes = {};
  for (const component of components) {
    const key = component.attribute;
    if (Object.prototype.hasOwnProperty.call(attributes, key)) {
      const existing = attributes[key];
      attributes[key] = Array.isArray(existing)
        ? [...existing, component.value]
        : [existing, component.value];
    } else {
      attributes[key] = component.value;
    }
  }

  const find = (name) =>
    components.find((c) => c.attribute.toUpperCase() === name.toUpperCase()) || null;

  const nnswf = find("NNSWF");
  const nswf = find("NSWF");
  const displayNameParts = [];
  if (nnswf?.value) displayNameParts.push(nnswf.value);
  if (nswf?.value) displayNameParts.push(nswf.value);

  const contactUris = components
    .filter((c) => c.attribute.toUpperCase() === "CONTACTURI")
    .map((c) => c.value);

  return {
    displayName: displayNameParts.length > 0 ? displayNameParts.join(" ").trim() : null,
    creature: attributes.Creature || attributes.creature || null,
    contactUris,
    webhookUrl: attributes.webhook_url || null,
    raw: rawDn.trim(),
    attributes
  };
}

module.exports = { parseUserSelectedDn };
