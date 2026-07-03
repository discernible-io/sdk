# Changelog

All notable changes to `@rodit/rodit-auth-be` are documented here.

## [9.12.0] — 2026-07-02

### Fixed

- **Multi-peer inbound webhook verification.** Inbound webhook signatures were
  verified against `stateManager.getPeerBase64urlJwkPublicKey()`, a single
  mutable "current peer" slot. When an agent was connected to several peers the
  slot was clobbered by the most recent peer, so webhooks from other senders
  (including the central API) failed with a false `401`
  `WEBHOOK_SIGNATURE_INVALID` / `PEER_KEY_UNAVAILABLE`.

### Added

- **Self-identifying webhooks.** The signer's Ed25519 public key now travels
  with each webhook, so verification no longer depends on a shared "current
  peer" slot and is correct when connected to many peers at once:
  - `send_webhook` advertises the signer identity via `X-Rodit-Public-Key`,
    `X-Rodit-Implicit-Account` (hex of the signing key), and `X-Rodit-Token-Id`.
  - `webhookHandler.extractWebhookSignerKey(headers)` reads that key directly
    (implicit account is authoritative on its own; a raw advertised key must
    agree with it). Exported from the package root as `extractWebhookSignerKey`.
- **Signer ↔ session authorization gate.** A valid signature only proves the
  sender holds the advertised private key; it does not prove that identity is a
  peer we established a session with. `createWebhookAuthenticationMiddleware`
  now enforces, after the signature verifies, that the (signed) `session_id`
  maps to a live session whose `ownerId` equals the verified signer's implicit
  account. New rejections: `401 WEBHOOK_SESSION_REQUIRED`,
  `401 WEBHOOK_SESSION_INVALID`, `403 WEBHOOK_SIGNER_SESSION_MISMATCH`
  (bypassed only under `NODE_ENV=test` or
  `SECURITY_OPTIONS.BYPASS_WEBHOOK_VERIFICATION`). The validated binding is
  exposed as `req.webhook_session`, `req.webhook_session_id`, and
  `req.webhook_signer_implicit_account`.
- **Webhook ↔ session correlation.** `send_webhook` stamps the originating
  session id into the **signed** payload (`session_id`) so receivers can link an
  inbound webhook to the session opened at login:
  - `extractWebhookSessionId({ headers, rawPayload, parsedBody })` returns the
    session id (signed payload authoritative, `X-Rodit-Session-Id` header as
    fallback). Exported from the package root and from `webhookHandler`.
  - `createPublicKeyMiddleware` sets `req.webhook_session_id` for downstream
    handlers.
  - The session id is resolved without requiring a request context: it falls
    back to **session storage** (the SessionManager singleton, in-memory by
    default) via `findSessionsByRoditId(options.sessionRoditId)`, so a JWT issuer
    (`login_client`) can stamp the shared session id for out-of-band webhooks.
  - `RoditClient.sendWebhook` / `sendWebhookToEndpoint` / `sendWakeHook` /
    `sendAgentHook` accept an `options` argument (`sessionId`, `sessionRoditId`)
    and default `sessionId` to the client's own `this.sessionId` (set at
    `login_server`), so a peer that initiated the login stamps its session
    automatically.
- **Client-side session recording (symmetric session store).** The
  `SessionManager` facility used by servers to track client sessions is now also
  used by clients to record the sessions they open:
  - `SessionManager.recordSession({ id, roditId, ... })` stores an
    externally-issued session under its own id (idempotent), tagged
    `origin: "client"`. `createSession` now tags issued sessions
    `origin: "server"`.
  - `SessionManager.hasSession(id)` quietly reports whether an id is a known,
    live session (no warn logs, no lastAccessedAt bump); `forgetSession(id)`
    removes one.
  - `RoditClient.login_server` records each opened session keyed by the server's
    roditId, so a client connected to many servers can cross-reference an inbound
    webhook's `session_id` to a live session (multi-peer safe, unlike the single
    `this.sessionId` slot). `clearSession` forgets it.
  - `RoditClient.isKnownSession(id)` cross-references a webhook's session id
    against the client's open sessions.
  - Issuer-side webhook session lookup only considers `origin !== "client"`
    sessions, so mutual peers don't cross-stamp.

### Changed

- **`createPublicKeyMiddleware`** extracts the verification key from the webhook
  itself (`extractWebhookSignerKey`) instead of the mutable
  `stateManager.getPeerBase64urlJwkPublicKey()` slot, and attaches
  `req.webhook_session_id`. Authentication (key from the webhook) and
  authorization (binding to a session) are now cleanly separated.

## [8.0.0] — 2026-05-02

### Breaking

- **`login_client` / `POST /api/login` body**
  - Signature field: prefer **`base64url_signature`**, or the same bytes under **`roditid_base64url_signature`** (for callers such as **`login_server`**). Sending **both** keys non-empty is **400** `LOGIN_PAYLOAD_DEPRECATED`.
  - Hard-deprecated keys (always **400** `LOGIN_PAYLOAD_DEPRECATED`): **`signature`**, **`account_id`**.
  - Identifiers: exactly **one** of **`roditid`** or **`accountid`** non-empty (both non-empty → **400** `LOGIN_IDENTIFIER_AMBIGUOUS`).
  - Error codes: **`MISSING_LOGIN_IDENTIFIER`**, **`MISSING_BASE64URL_SIGNATURE`** (400, flat `{ error, message, requestId }`).

- **Outbound login (`login_server`, `login_portal`)**  
  Request bodies keep **`roditid_base64url_signature`** on the wire (stable field name for peers). **`login_portal`**: `roditid`, `timestamp`, `roditid_base64url_signature`. **`login_server`**: `timestamp`, `roditid_base64url_signature`, plus **`roditid`** and/or **`accountid`** per signing mode.

- **Peer resolution vs verification**
  - **`resolve_peer_rodit_for_login(roditid, accountid)`** — fetch by rodit id first, then by account id (see implementation).
  - **`verify_peer_rodit(peer_rodit, peerroditid, timestamp, signature)`** — timestamp, ownership, match, live, active, trust (no chain fetch).
  - Removed **`verify_peerrodit_getrodit`** and **`verify_peeraccount_getrodit`** (call **`resolve_peer_rodit_for_login`** then **`verify_peer_rodit`**).

### Fixed

- Removed an invalid synchronous **`require('jose')`** in `tokenservice.js` (jose is ESM-only); signing paths already use dynamic `import('jose')`.

### Migration from 7.x

```javascript
// Before (7.x)
await fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    roditid,
    timestamp,
    roditid_base64url_signature: sig,
    // or account_id — removed
  }),
});

// After (8.x)
await fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    roditid,           // and/or accountid (hex)
    timestamp,
    base64url_signature: sig,
  }),
});
```

Rename fields only; signing payload remains **`identifier + timestamp_iso`** where identifier is the same string you send as `roditid` or `accountid` per the resolution rule above.
