# Discernible IO SDK monorepo

RODiT authentication SDKs and HOLA verification tools for IdentyClaw.

| Package | Directory | npm | Used by |
|---------|-----------|-----|---------|
| @rodit/rodit-auth-be | [rodit-auth-be/](rodit-auth-be/) | [npm](https://www.npmjs.com/package/@rodit/rodit-auth-be) | OpenClaw A2A & webhooks plugins, custom APIs |
| @rodit/rodit-auth-fe | [rodit-auth-fe/](rodit-auth-fe/) | [npm](https://www.npmjs.com/package/@rodit/rodit-auth-fe) | Browser / NEP-413 clients |
| @rodit/verify-hola | [verify-hola/](verify-hola/) | [npm](https://www.npmjs.com/package/@rodit/verify-hola) | Verify-before-execute CLI & library |

## IdentyClaw stack

| Layer | Repo |
|-------|------|
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
