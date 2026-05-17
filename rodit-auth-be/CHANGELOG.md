# Changelog

All notable changes to `@rodit/rodit-auth-be` are documented here.

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
