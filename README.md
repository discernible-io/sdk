# RODiT SDK monorepo

Source for the npm packages that power [**RODiT**](https://www.discernible.io)-based APIs: blockchain-verified identity, mutual authentication, JWT sessions, route permissions, webhooks, and federated login across sibling APIs in the same token family.

| Package | Directory | npm | Role |
|---------|-----------|-----|------|
| [@rodit/rodit-auth-be](https://www.npmjs.com/package/@rodit/rodit-auth-be) | [rodit-auth-be/](rodit-auth-be/) | [npm](https://www.npmjs.com/package/@rodit/rodit-auth-be) | Node.js / Express server SDK — login, JWT, permissions, webhooks |
| [@rodit/rodit-auth-fe](https://www.npmjs.com/package/@rodit/rodit-auth-fe) | [rodit-auth-fe/](rodit-auth-fe/) | [npm](https://www.npmjs.com/package/@rodit/rodit-auth-fe) | Browser / NEP-413 client SDK |
| @rodit/verify-hola | [verify-hola/](verify-hola/) | [npm](https://www.npmjs.com/package/@rodit/verify-hola) | Verify-before-execute HOLA CLI & library |

## What is RODiT?

**RODiT** (Routable Decentralized Identity Token) is a NEAR on-chain credential format. Each token carries metadata — API URL, permissioned routes, rate limits, webhook targets, JWT lifetime, geographic and CIDR constraints — signed by a service provider. APIs built on this SDK use that metadata to authenticate peers, mint JWTs, enforce permissions, and send signed webhooks.

Typical stack:

- **Server** — [`@rodit/rodit-auth-be`](https://www.npmjs.com/package/@rodit/rodit-auth-be): Express middleware, `POST /api/login`, session manager, outbound webhooks.
- **Browser / wallet client** — [`@rodit/rodit-auth-fe`](https://www.npmjs.com/package/@rodit/rodit-auth-fe): NEP-413 wallet login, JWT refresh, authenticated `fetch`.
- **Agents & integrations** — OpenClaw plugins, HOLA verify tooling, MCP discovery on live APIs.

## Production APIs powered by this SDK

These public APIs (and their open-source deploy templates where published) run on `@rodit/rodit-auth-be` and/or `@rodit/rodit-auth-fe`:

| API | Notes | Source / contract |
|-----|-------|-------------------|
| [api.identyclaw.com](https://api.identyclaw.com) | IdentyClaw agent platform — MCP discovery, HOLA, federation | [discernible-io/api-idc](https://github.com/discernible-io/api-idc) · [MCP discovery](https://api.identyclaw.com/.well-known/mcp) |
| [api.lastcradle.io](https://api.lastcradle.io) | RODiT-authenticated API in the Last Cradle family | — |
| *Many others* | Same SR/CR token family; federated login across sibling `subjectuniqueidentifier_url` endpoints | Deploy with [rodit-auth-be](rodit-auth-be/README.md) |

To build a new RODiT-powered API: install [`@rodit/rodit-auth-be`](https://www.npmjs.com/package/@rodit/rodit-auth-be), wire `RoditClient.create('server')`, expose `/api/login`, and protect routes with `authenticate` + `authorize`. For web clients, add [`@rodit/rodit-auth-fe`](https://www.npmjs.com/package/@rodit/rodit-auth-fe). See [rodit-auth-be/README.md](rodit-auth-be/README.md) for the full server guide.

## IdentyClaw stack

| Layer | Repo |
|-------|------|
| **This SDK** | [`@rodit/rodit-auth-be`](https://www.npmjs.com/package/@rodit/rodit-auth-be) · [`@rodit/rodit-auth-fe`](https://www.npmjs.com/package/@rodit/rodit-auth-fe) |
| IdentyClaw API | [api-idc](https://github.com/discernible-io/api-idc) → [api.identyclaw.com](https://api.identyclaw.com) |
| Deploy template | [identyclaw-agents](https://github.com/discernible-io/identyclaw-agents) |
| OpenClaw plugins | [tools](https://github.com/discernible-io/openclaw-identyclaw-plugin), [A2A](https://github.com/discernible-io/openclaw-a2a-idc-plugin), [webhooks](https://github.com/discernible-io/openclaw-identyclaw-webhooks-plugin) |
| NEAR account CLI | [gennearaccount](https://github.com/discernible-io/gennearaccount) |
| API contract | [api.identyclaw.com/.well-known/mcp](https://api.identyclaw.com/.well-known/mcp) |
| Product | [discernible.io](https://www.discernible.io) |

## Quick start — verify HOLA (recommended)

No IdentyClaw API in the verify path — your machine reads chain state via FastNear (or any NEAR RPC).

```bash
export NEAR_RPC_URL="https://rpc.mainnet.fastnear.com"
export NEAR_CONTRACT_ID="genaaaa-identyclaw-com.near"

npx @rodit/verify-hola report "HOLA/MUNDO/..." --rpc \
  --canonical-peer <lemuel-gulliver-lobby-tokenId>
```

From this monorepo (no npm publish required):

```bash
export NEAR_RPC_URL="https://rpc.mainnet.fastnear.com"
export NEAR_CONTRACT_ID="genaaaa-identyclaw-com.near"
node verify-hola/bin/verify-hola.js report "HOLA/..." --rpc \
  --canonical-peer <lemuel-gulliver-lobby-tokenId>
```

### Alternative: IdentyClaw API path

JWT is optional — `POST /api/identity/verify` is public.

```bash
npx @rodit/verify-hola report "HOLA/MUNDO/..."
```

## Package docs

- [rodit-auth-be/README.md](rodit-auth-be/README.md) — Node/Express mutual auth
- [rodit-auth-fe/README.md](rodit-auth-fe/README.md) — browser SDK
- [verify-hola/README.md](verify-hola/README.md) — HOLA verification CLI

---

[discernible.io](https://www.discernible.io) · [identyclaw-agents](https://github.com/discernible-io/identyclaw-agents) · [discernible-io](https://github.com/discernible-io)
