const test = require("node:test");
const assert = require("node:assert/strict");
const { parseUserSelectedDn } = require("../lib/parse-dn");
const { extractProfileFromDid } = require("../lib/report");

test("parseUserSelectedDn extracts multi ContactURI", () => {
  const dn =
    "NNSWF=Lemuel Gulliver,Creature=Onboarding Agent,ContactURI=a2a:identyclaw.com:https://identyclaw-concierge.identyclaw.com:7443,ContactURI=email:identyclaw.com:concierge@identyclaw.com";
  const parsed = parseUserSelectedDn(dn);
  assert.equal(parsed.displayName, "Lemuel Gulliver");
  assert.equal(parsed.creature, "Onboarding Agent");
  assert.equal(parsed.contactUris.length, 2);
});

test("extractProfileFromDid maps RoditTokenMetadata", () => {
  const did = {
    id: "did:rodit:abcdefghijkl",
    controller: "holder.near",
    service: [
      {
        type: "RoditTokenMetadata",
        serviceEndpoint: {
          tokenId: "abcdefghijkl",
          ownerAccountId: "holder.near",
          metadata: {
            userselected_dn:
              "NNSWF=Demo Agent,Creature=Bot,ContactURI=email:example.com:agent@example.com"
          }
        }
      }
    ]
  };
  const profile = extractProfileFromDid(did);
  assert.equal(profile.tokenId, "abcdefghijkl");
  assert.equal(profile.displayName, "Demo Agent");
  assert.equal(profile.contactUris[0], "email:example.com:agent@example.com");
});
