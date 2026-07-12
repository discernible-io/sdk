# @rodit/verify-hola

Verify-before-execute tooling for IdentyClaw HOLA lines.

For NEAR account enrollment, see [gennearaccount](https://github.com/discernible-io/gennearaccount). For in-gateway HOLA tools, see [openclaw-identyclaw-plugin](https://github.com/discernible-io/openclaw-identyclaw-plugin).

## Recommended: direct NEAR RPC (`--rpc`)

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
node examples/verify-before-execute/verify-hola-rpc.mjs "HOLA/..."
```

## Alternative: IdentyClaw API path

JWT is optional — `POST /api/identity/verify` is public.

```bash
npx @rodit/verify-hola report "HOLA/MUNDO/..."
```

## Commands

| Command | Description |
| --- | --- |
| `verify-hola verify "HOLA/..." --rpc` | Cryptographic outcome via NEAR RPC |
| `verify-hola report "HOLA/..." --rpc` | Verify + on-chain passport profile (DN) |
| `verify-hola report "HOLA/..."` | Verify + profile via API (`includeProfile`) |

## Environment

| Variable | `--rpc` | API (default) |
| --- | --- | --- |
| `NEAR_RPC_URL` | **Required** | — |
| `NEAR_CONTRACT_ID` | **Required** | — |
| `IDENTYCLAW_BASE_URL` | — | default `https://api.identyclaw.com` |
| `IDENTYCLAW_JWT` | — | optional |
| `IDENTYCLAW_CANONICAL_PEER_ID` | optional impersonation guard | optional |
| `IDENTYCLAW_EXPECTED_RECIPIENT` | — | optional |

## Concierge demo (Lemuel Gulliver)

1. Message **Lemuel Gulliver** via A2A at [identyclaw-concierge.identyclaw.com:7443](https://identyclaw-concierge.identyclaw.com:7443) (or email / Discord / Telegram) and ask for a HOLA.
2. Verify with RPC (recommended):

```bash
export NEAR_RPC_URL="https://rpc.mainnet.fastnear.com"
export NEAR_CONTRACT_ID="genaaaa-identyclaw-com.near"
export IDENTYCLAW_CANONICAL_PEER_ID="<lobby-tokenId-from-agent-card>"
npx @rodit/verify-hola report "HOLA/..." --rpc
```

Registry: [com.identyclaw.lemuel_gulliver](https://www.a2a-registry.org/agent/com.identyclaw.lemuel_gulliver)

Web UI (API path): https://verify.identyclaw.com

## API

```javascript
const { buildHolaReportViaRpc } = require("@rodit/verify-hola/lib/verify-rpc");

const report = await buildHolaReportViaRpc(hola, {
  nearRpcUrl: process.env.NEAR_RPC_URL,
  nearContractId: process.env.NEAR_CONTRACT_ID,
  canonicalPeerId: "abcdefghijkl"
});
```

## Related

- [`references/verify-hola-recipes.md`](../references/verify-hola-recipes.md)
- [`references/identity-verification-policy.md`](../references/identity-verification-policy.md) §1
- MCP `doc:reference:verify-hola-recipes`
