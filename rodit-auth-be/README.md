# RODiT Authentication SDK

A comprehensive Node.js SDK for implementing RODiT-based mutual authentication, authorization, self-configuration, and session management in Express.js applications.

**Version:** 9.13.0  
**License:** Proprietary  
**Author:** Discernible IO

**Login `POST` /api/login:** Use **`accountid`** (or **`roditid`**), **`timestamp`**, and **`base64url_signature`**. Sign UTF-8 bytes of `identifier + timestamp_iso`, and reject deprecated keys such as **`signature`** and **`account_id`**. See [CHANGELOG.md](./CHANGELOG.md).

**9.13 federated login:** A client RODiT issued for API A can log into API B in the same SR/CR family via `login_server({ apiEndpoint })`. See [Federated login](#federated-login-same-family-different-api-url).

## Table of Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Installation & Setup](#installation--setup)
- [Authentication](#authentication)
  - [Login Mode Control](#login-mode-control)
  - [Federated login](#federated-login-same-family-different-api-url)
- [Authorization & Permissions](#authorization--permissions)
- [Session Management](#session-management)
  - [Session lifetime and TTL](#session-lifetime-and-ttl)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Session Storage Configuration](#session-storage-configuration)
  - [Configuration Priority](#configuration-priority)
- [Logging & Monitoring](#logging--monitoring)
- [Performance Tracking](#performance-tracking)
- [Webhooks](#webhooks)
- [Advanced Usage](#advanced-usage)
  - [Portal Authentication](#portal-authentication-server-to-server)
  - [SignPortal URL Configuration](#signportal-url-configuration)
  - [CRUDA Operations Example](#cruda-operations-example)
- [API Reference](#api-reference)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Installation

```bash
npm install @rodit/rodit-auth-be
```

### Basic Server Setup

```javascript
const express = require('express');
const { RoditClient } = require('@rodit/rodit-auth-be');
const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager');
const { ulid } = require('ulid');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();

// Configure session storage BEFORE initializing RoditClient
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: './data',
  table: 'sessions',
});
setExpressSessionStore(sessionStore);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || ulid();
  req.startTime = Date.now();
  next();
});

async function startServer() {
  try {
    const roditClient = await RoditClient.create('server');
    app.locals.roditClient = roditClient;

    const logger = roditClient.getLogger();
    app.use(roditClient.getLoggingMiddleware());

    const authenticate = (req, res, next) => roditClient.authenticate(req, res, next);
    const authenticateLogout = (req, res, next) =>
      roditClient.authenticateForLogout(req, res, next);
    const authorize = (req, res, next) => roditClient.authorize(req, res, next);

    app.post('/api/login', (req, res) => {
      req.logAction = 'login-attempt';
      roditClient.login_client(req, res);
    });
    app.post('/api/logout', authenticateLogout, (req, res) => {
      req.logAction = 'logout-attempt';
      roditClient.logout_client(req, res);
    });
    app.get('/api/protected', authenticate, (req, res) => {
      res.json({ message: 'Protected data', user: req.user });
    });
    app.use('/api/admin', authenticate, authorize, adminRoutes);

    const port = 3000;
    app.listen(port, () => {
      logger.info(`RODiT Authentication Server running on port ${port}`);
    });
  } catch (error) {
    console.error('Server initialization failed:', error);
    process.exit(1);
  }
}

startServer();
```

## Core Concepts

### The RoditClient Pattern

The SDK centers around the `RoditClient` class, which provides a unified interface for all RODiT operations:

- **Single Initialization**: Create once with `RoditClient.create(role)` where role is `'server'`, `'client'`, or `'portal'`
- **Shared Instance**: Store in `app.locals` for access across routes and middleware
- **Self-Configuring**: Automatically loads configuration from Vault, files, or environment variables
- **Encapsulated**: All SDK functionality accessed through the client instance
- **Session Management**: Built-in session tracking with pluggable storage backends
- **Performance Monitoring**: Integrated request tracking and metrics collection

### App.locals Pattern

Store the initialized client in `app.locals` for consistent access across your application:

```javascript
// In main app.js
const roditClient = await RoditClient.create('server')
app.locals.roditClient = roditClient
// In route modules
const router = express.Router()
router.get('/data', (req, res) => {
  const client = req.app.locals.roditClient
  const logger = client.getLogger()
  logger.info('Processing request', {
    component: 'DataRoute',
    userId: req.user?.id
  })
res.json({ data: 'example' })
})
```

### Authentication Middleware Pattern

Create middleware functions that delegate to the RoditClient:

```javascript
// Create reusable middleware
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authentication service unavailable' })
  }
client.authenticate(req, res, next)
}
const authorize = (req, res, next) => {
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authorization service unavailable' })
  }
client.authorize(req, res, next)
}
// Use in routes
app.get('/api/protected', authenticate, handler)
app.post('/api/admin', authenticate, authorize, adminHandler)
```

## Installation & Setup

### Dependencies

**Required:**
```bash
npm install @rodit/rodit-auth-be express config winston
```

**Recommended for main:**
```bash
npm install express-session connect-sqlite3
```

**Optional:**
```bash
npm install node-vault  # For Vault-based credentials
npm install winston-loki  # For Grafana Loki logging
```

### Environment Variables

**Vault Configuration (main):**
```bash
export RODIT_NEAR_CREDENTIALS_SOURCE=vault
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
export SERVICE_NAME=your-service-name
export NEAR_CONTRACT_ID=discernible-io.near
```

**Application Configuration:**
```bash
export NODE_ENV=main  # Environment: main, development, test
export LOG_LEVEL=info       # Logging: error, warn, info, debug, trace
export API_DEFAULT_OPTIONS_DB_PATH=/app/data/database.sqlite
```

**Session Configuration:**
```bash
export SESSION_STORAGE_TYPE=express-session  # Storage: memory, express, express-session
export SESSION_CLEANUP_INTERVAL=3600000      # Cleanup interval in milliseconds (1 hour)
export SESSION_TOKEN_RETENTION_PERIOD=604800 # Token retention in seconds (7 days)
export SESSION_VALIDATION_CACHE_TTL=5000     # Cache TTL in milliseconds (5 seconds)
```

**Logging Configuration:**
```bash
export LOKI_URL=https://loki.example.com:3100
export LOKI_BASIC_AUTH=username:password
```

### Configuration Files

Create `config/default.json`:

```json
{
"NEAR_CONTRACT_ID": "discernible-io.near",
"SERVICE_NAME": "your-service",
"SECURITY_OPTIONS": {
"SILENT_LOGIN_FAILURES": false,
"SESSION_TTL_SECONDS": 5200
"FALLBACK_JWT_DURATION": 3600
}
}
```

## Authentication

### RODiT-Based Authentication

RODiT provides cryptographic mutual authentication using blockchain-verified identities.

#### Client Login Request

For API login documentation, use **`accountid`** with HTTP `POST /api/login`. The signed payload is **`accountid + timestamp_iso`** (no separator).

| Field | Description |
|-------|-------------|
| `timestamp` | Recommended; Unix seconds from `GET /api/login/timestamp` |
| `base64url_signature` | Ed25519 detached signature (base64url) over `accountid + timestamp_iso` |
| `accountid` | 64-hex implicit NEAR account login identifier |

```json
{
  "accountid": "<64-char-hex>",
  "timestamp": 1640995200,
  "base64url_signature": "base64url-encoded-signature"
}
```

Use **`base64url_signature`** in login payloads for API login examples.

Rejected keys (HTTP 400, `LOGIN_PAYLOAD_DEPRECATED`): **`signature`** and **`account_id`**.

#### Server Response

```json
{
  "jwt_token": "<jwt-token>",
  "requestId": "01HQXYZ123ABC"
}
```

#### Authentication Flow

1. **Client sends RODiT credentials** - RODiT ID or account ID, timestamp, and cryptographic signature
2. **SDK verifies signature** - Validates against blockchain records (NEAR Protocol)
3. **Session created** - New session stored in session manager
4. **JWT token issued** - Token contains session ID, user claims, and always
   `rodit_subjectuniqueidentifier_url` (`null` same-API; federated API URL when
   peer home ≠ issuing server). See [Federated login](#federated-login-same-family-different-api-url).
5. **Subsequent requests** - Client sends JWT in `Authorization: Bearer <token>` header
6. **Token validation** - SDK validates JWT (issuer rules differ for federated vs
   same-API) and checks session status

Security hardening in current implementation:
- JWT compact parts must be canonical base64url (non-canonical encodings are rejected).
- Session registration is enforced during JWT validation (unknown/inactive/expired sessions are rejected).
- Server session length defaults to `SECURITY_OPTIONS.SESSION_TTL_SECONDS` (5200 s); see [Session lifetime and TTL](#session-lifetime-and-ttl).
- Token renewal uses `sessionManager` for session checks and updates (no `stateManager` session mutations).
- Federated `login_server({ apiEndpoint })` rejects MITM when the signed
  `rodit_subjectuniqueidentifier_url` does not match the intended endpoint.

### Login Implementation

```javascript
// routes/login.js
const express = require('express')
const router = express.Router()
router.post('/login', async (req, res) => {
  req.logAction = 'login-attempt'
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authentication service unavailable' })
  }
// Delegate to SDK's login_client method
await client.login_client(req, res)
})
module.exports = router
```

### Logout Implementation

```javascript
// Logout invalidates the JWT token and closes the session
// Use logout-specific auth so signature-valid expired tokens can still logout.
router.post('/logout', authenticateLogout, async (req, res) => {
  req.logAction = 'logout-attempt'
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authentication service unavailable' })
  }
// Delegate to SDK's logout_client method
await client.logout_client(req, res)
})
```

### Protected Routes

```javascript
// Require authentication for access
app.get('/api/data', authenticate, (req, res) => {
  // req.user contains authenticated user information
  const logger = req.app.locals.roditClient.getLogger()
  logger.info('Protected route accessed', {
    component: 'API',
    userId: req.user.id,
    roditId: req.user.roditId,
    requestId: req.requestId
  })
res.json({
  message: 'Authenticated data',
  user: req.user,
  requestId: req.requestId
})
})
```

### Authentication Middleware

The `authenticate` middleware validates JWT tokens and populates `req.user`:

```javascript
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient
  client.authenticate(req, res, next)
}
// After successful authentication, req.user contains:
// {
  // id: 'user-unique-id',
  // roditId: '01K4G3D95QF6NR0RSJK9WEK6KA',
  // aud: 'audience',
  // iss: 'issuer',
  // exp: 1640999999,
  // iat: 1640995200,
  // session_id: '01HQXYZ123ABC'
  // }
```

### Login Mode Control

The SDK provides configurable access control for RODiT authentication, allowing you to restrict which types of logins are accepted by your server.

#### Login Types

**Partner Login (Client-Server)**
- **Definition**: Authentication where the peer's service provider ID is **different** from the server's service provider ID
- **Use Case**: Traditional client-server authentication where a client authenticates to a service provider
- **Example**: A mobile app (client) authenticating to your API server

**Peer Login (Peer-to-Peer)**
- **Definition**: Authentication where the peer's service provider ID is **the same** as the server's service provider ID
- **Use Case**: Peer-to-peer authentication between entities with the same service provider
- **Example**: Two servers in the same organization authenticating to each other

#### Configuration Options

| Mode | Partner Logins | Peer Logins | Description |
|------|---------------|-------------|-------------|
| `partner` | ✅ Accepted | ❌ Rejected | **Default** - Only accept client-server authentication |
| `promiscuous` | ✅ Accepted | ✅ Accepted | Accept all valid logins regardless of type |
| `p2p` | ❌ Rejected | ✅ Accepted | Only accept peer-to-peer authentication |

#### Usage Examples

**Default (Partner Only):**
```bash
// No configuration needed - this is the default
// Only client-server authentication is accepted
```

**Accept All Logins:**
```bash
export SECURITY_OPTIONS_LOGIN_MODE=promiscuous
// Both Partner and Peer logins are accepted
```

**Peer-to-Peer Only:**
```bash
export SECURITY_OPTIONS_LOGIN_MODE=p2p
// Only peer-to-peer authentication is accepted
```

**Docker/Podman:**
```bash
podman run -e SECURITY_OPTIONS_LOGIN_MODE=partner ...
```

**GitHub Actions:**
Add repository variable:
- **Name**: `SECURITY_OPTIONS_LOGIN_MODE`
- **Value**: `partner` | `promiscuous` | `p2p`

#### Federated login (same family, different API URL)

Enable a client RODiT issued for API A (`subjectuniqueidentifier_url`) to log
into API B in the **same SR/CR family**. Federation is **login → remint a local
JWT** on B; foreign JWTs are not accepted without re-login. Mutual auth remains
optional (no reverse `login_server` required).

##### Client call

```js
const { RoditClient } = require('@rodit/rodit-auth-be');

const client = await RoditClient.create('client');
await client.login_server({
  apiEndpoint: 'https://api-b.example.com', // federated API; omit for home API
});
```

When `apiEndpoint` is omitted, login targets the client's own
`subjectuniqueidentifier_url` (same-API path).

##### JWT claim contract

Unset fields are **always present as `null`** (same rule as `config_*` in 9.12).
Do not omit `rodit_subjectuniqueidentifier_url` on same-API tokens.

| Claim | Always present? | Same-API login | Federated login |
|-------|-----------------|----------------|-----------------|
| `iss` | yes | peer home URL (= server URL in practice) | **client home** `subjectuniqueidentifier_url` |
| `aud` | yes | server `owner_id` | server `owner_id` (federated API) |
| `rodit_subjectuniqueidentifier_url` | **yes** | **`null`** | **federated API** `subjectuniqueidentifier_url` |
| `config_iso639` / `config_iso3166` / `config_iso15924` / `config_timeoptions` | yes | `null` | `null` |

A JWT is treated as federated when:

```js
rodit_subjectuniqueidentifier_url != null
  && String(rodit_subjectuniqueidentifier_url).trim() !== ""
```

(Helper: `isNonEmptyUrlClaim`.)

##### Server validation

After signature verification:

- **Federated JWT** — `rodit_subjectuniqueidentifier_url` must equal this
  server's URL; `iss` must equal the login client's home URL (resolved from
  `sub` via on-chain RODiT).
- **Same-API / 9.12 tokens** — claim null/absent → `iss` must equal this
  server's URL (unchanged 9.12 issuer rule).
- **`aud`**, family match, and `LOGIN_MODE` are unchanged.

##### Client MITM check

After crypto validation of the received JWT, `login_server` checks that a
federated attempt (`apiEndpoint` ≠ client home) has:

1. Non-empty `rodit_subjectuniqueidentifier_url`
2. That claim equal to the intended `apiEndpoint`
3. `iss` equal to the client home URL

| Failure | `errorCode` |
|---------|-------------|
| Null/empty federated claim | `FEDERATED_ISSUER_MISSING` |
| Claim or `iss` mismatch | `FEDERATED_ISSUER_MISMATCH` |

##### Renewal

- Federated JWT renewals preserve the non-null claim string.
- Tokens minted by 9.12 (no claim) renew into `rodit_subjectuniqueidentifier_url: null`.

##### Operational prerequisites (outside SDK)

- Federated server RODiT shares the same `bc=;sc=;id=SR;id=CR` family.
- Federated domain has DNS trust TXT (keyed off **own**
  `subjectuniqueidentifier_url`).
- Client calls `login_server({ apiEndpoint: '<federated URL>' })`.
- Client→server federation needs `LOGIN_MODE=partner` (or `promiscuous`); a
  server RODiT logging into a federated API under `partner` is still rejected
  by existing role-separation policy.

##### Helpers (package root)

```js
const {
  normalizeUrlWithoutPort,
  isNonEmptyUrlClaim,
  isFederatedRoditLogin,
  validateFederatedLoginTarget,
} = require('@rodit/rodit-auth-be');
```

#### Logging and Monitoring

**Successful Login:**
```json
{
  "level": "info",
  "message": "PARTNER login verified successfully",
  "verificationType": "PARTNER",
  "loginMode": "partner",
  "duration": 1234
}
```

**Rejected Login:**
```json
{
  "level": "warn",
  "message": "PEER login rejected by LOGIN_MODE policy",
  "verificationType": "PEER",
  "loginMode": "partner",
  "policyReason": "LOGIN_MODE=partner does not accept PEER logins"
}
```

**Metrics:**
- `rodit_match_verification` with `result: "success"` - Successful authentication
- `rodit_match_verification` with `result: "policy_rejected"` - Rejected by policy

#### Security Considerations

1. **Default is Secure**: The default `partner` mode provides the most restrictive access control
2. **Promiscuous Mode**: Use only when you need to accept both types of authentication
3. **P2P Mode**: Use when building peer-to-peer systems where only same-provider authentication is needed
4. **Policy Enforcement**: Rejections are logged with clear reasons for audit trails
5. **Federated MITM**: Always pass the real peer URL as `apiEndpoint`; the client
   verifies the signed federated issuer claim against that URL after login

#### Troubleshooting

**Login Rejected with "policy_rejected":**
- If you see "PEER login rejected" and need to accept peer logins, set mode to `promiscuous` or `p2p`
- If you see "PARTNER login rejected" and need to accept partner logins, set mode to `promiscuous` or `partner`

**Federated login failures:**
- `FEDERATED_ISSUER_MISSING` — JWT has null/empty `rodit_subjectuniqueidentifier_url` but `apiEndpoint` differs from client home (peer may be pre-9.13, or claim omitted incorrectly)
- `FEDERATED_ISSUER_MISMATCH` — claim or `iss` does not match intended `apiEndpoint` / client home (wrong URL or MITM)
- `Error 005: Invalid federated issuer` on the server — JWT federated claim is not this server's `subjectuniqueidentifier_url`

**Check Current Mode:**
Look for the log message during authentication:
```
"Starting RODiT match verification" with "loginMode": "partner"
```

## Authorization & Permissions

### Route-Based Permissions

Permissions are configured in your RODiT token metadata using the `permissioned_routes` field:

```json
{
  "permissioned_routes": {
    "entities": {
      "/": {
        "methods": "+0"
      },
      "/api/echo": {
        "methods": "+0"
      },
      "/api/cruda/create": {
        "methods": "+0"
      },
      "/api/cruda/list": {
        "methods": "+0"
      },
      "/api/admin": {
        "methods": "+0"
      }
    }
  }
}
```

**Permission Format:**
- `"+0"` = All methods allowed (GET, POST, PUT, DELETE, etc.)
- `"+1"` = GET only
- `"+2"` = POST only
- Custom combinations can be defined

### Permission Validation Middleware

The `authorize` middleware validates that the authenticated user has permission to access the requested route:

```javascript
const authenticate = (req, res, next) => {
  req.app.locals.roditClient.authenticate(req, res, next)
}
const authorize = (req, res, next) => {
  req.app.locals.roditClient.authorize(req, res, next)
}
// Apply both authentication and authorization
app.use('/api/admin', authenticate, authorize, adminRoutes)
// CRUDA endpoints with full protection
app.use('/api/cruda', authenticate, authorize, crudaRoutes)
```

### Permission Enforcement

```javascript
// Example: CRUDA routes with permission checking
const router = express.Router()
// All routes require authentication + authorization
router.post('/create', async (req, res) => {
  // User must have permission for POST /api/cruda/create
  const { comment, author } = req.body
  // Create record in database
  const result = await db.run(
  'INSERT INTO comments (comment, author) VALUES (?, ?)',
  [comment, author || req.user.roditId]
  )
  res.json({ id: result.lastID, requestId: req.requestId })
})
router.post('/list', async (req, res) => {
  // User must have permission for POST /api/cruda/list
  const records = await db.all('SELECT * FROM comments ORDER BY created_at DESC')
  res.json({ records, requestId: req.requestId })
})
module.exports = router
```

### Dynamic Permission Checking

```javascript
// Check permissions programmatically
const client = req.app.locals.roditClient
const hasPermission = client.isOperationPermitted('POST', '/api/admin/users')
if (!hasPermission) {
  res.status(403).json({
    error: 'Forbidden',
    message: 'You do not have permission to access this resource',
    requestId: req.requestId
  })
}
// Proceed with operation
```

### Permission Validation in Client Token Minting

When minting client tokens via `/api/signclient`, the server validates that requested permissions are a subset of the server's own permissions:

```javascript
// Client requests these permissions:
const requestedPermissions = {
  "/": "+0",
  "/api/echo": "+0",
  "/api/cruda/create": "+0"
}
// Server validates against its own permissioned_routes
// If any requested route is not in server's config, request is rejected with HTTP 400
```

## Session Management

### Overview

The SDK includes a comprehensive session management system that:
- Tracks active user sessions
- Validates JWT tokens against session state
- Supports pluggable storage backends
- Automatically cleans up expired sessions
- Integrates with performance metrics

### Session lifetime and TTL

Server sessions and JWT access credentials use **different** clocks:

| Concept | Controlled by | Stored / carried as |
|---------|----------------|---------------------|
| **Server session** | `SECURITY_OPTIONS.SESSION_TTL_SECONDS` (host config) | `sessionManager` record `expiresAt`; JWT claim `session_exp` |
| **Access credential (JWT `exp`)** | Passport `jwt_duration` on peer/own RODiT metadata (+ renewal) | JWT `exp`; renewed until `session_exp` |

You do **not** need to change on-chain `jwt_duration` on the server RODiT token to control how long a **session** lasts. Set session length in application config instead.

#### `SECURITY_OPTIONS.SESSION_TTL_SECONDS`

| Property | Value |
|----------|--------|
| **SDK default** | `5200` (~87 minutes) |
| **Valid range** | `60` – `31536000` (365 days), or `0` to disable |
| **Config path** | `SECURITY_OPTIONS.SESSION_TTL_SECONDS` |
| **Env example** | `SECURITY_OPTIONS_SESSION_TTL_SECONDS=2592000` (30 days, with node-config style mapping) |

At login the SDK computes:

```text
session_expiresAt = login_time + SESSION_TTL_SECONDS
```

Then applies **passport caps**: if either peer or own RODiT has a bounded `not_after`, the session cannot end later than the **earlier** of those dates.

Set **`SESSION_TTL_SECONDS` to `0`** to fall back to passport-derived session end (bounded `not_after` when present, otherwise `max(peer, own) jwt_duration`).

#### Examples

**Default (5200 seconds):**

```javascript
// config/default.json — omit SESSION_TTL_SECONDS to use SDK default 5200
{
  "SECURITY_OPTIONS": {
    "FALLBACK_JWT_DURATION": 3600
  }
}
```

**30-day sessions:**

```javascript
{
  "SECURITY_OPTIONS": {
    "SESSION_TTL_SECONDS": 2592000
  }
}
```

**Passport-derived session length (legacy):**

```javascript
{
  "SECURITY_OPTIONS": {
    "SESSION_TTL_SECONDS": 0
  }
}
```

#### Enforcement on each API request

For normal API authentication (`authenticate_apicall`), the SDK:

1. Checks stored session: exists, `status === 'active'`, `expiresAt` not in the past.
2. Validates JWT signature and `exp` (with renewal when eligible).
3. Requires JWT `session_exp` to match stored `expiresAt` when session registration is enforced.

Portal/outbound login token validation can skip session registration when `SECURITY_OPTIONS.RELAXED_SESSION_VALIDATION` is `true` (default).

#### Related options

| Option | Purpose |
|--------|---------|
| `FALLBACK_JWT_DURATION` | Access-token lifetime when passport `jwt_duration` is missing or invalid (default `3600`; max 7 days in validator) |
| `JWT_MAX_DURATION_SECONDS_RODIT_UNBOUNDED` | Cap on JWT `exp` when peer `not_after` is unbounded |
| `RELAXED_SESSION_VALIDATION` | Portal/outbound flows may skip server session lookup |
| `SESSION_VALIDATION_CACHE_TTL` | Cache TTL for session invalidation checks after logout |

### Session Storage Backends

#### 1. In-Memory Storage (Default)

No configuration needed - works out of the box:

```javascript
const client = await RoditClient.create('server')
// Uses InMemorySessionStorage by default
```

**Pros:** Fast, zero configuration  
**Cons:** Sessions lost on server restart, not suitable for multi-server deployments

#### 2. SQLite Storage (Recommended for main)

Persistent storage using SQLite database:

```javascript
const express = require('express')
const session = require('express-session')
const SQLiteStore = require('connect-sqlite3')(session)
const { RoditClient } = require('@rodit/rodit-auth-be')
const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
// Configure BEFORE initializing RoditClient
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: './data',
  table: 'sessions'
})
setExpressSessionStore(sessionStore)
// Now initialize client
const client = await RoditClient.create('server')
```

**Pros:** Persistent across restarts, simple setup, uses existing database infrastructure  
**Cons:** Not suitable for multi-server deployments

#### 3. Redis Storage (For Multi-Server)

```bash
npm install express-session connect-redis redis
```

```javascript
const session = require('express-session')
const RedisStore = require('connect-redis').default
const { createClient } = require('redis')
const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
// Create Redis client
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
})
await redisClient.connect()
// Create Redis store
const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'rodit:sess:',
  ttl: 86400 // 24 hours
})
setExpressSessionStore(redisStore)
const client = await RoditClient.create('server')
```

**Pros:** Shared sessions across multiple servers, high performance  
**Cons:** Requires Redis infrastructure

### Session Storage Configuration

The SDK supports configurable session storage via the `SESSION_STORAGE_TYPE` environment variable.

#### Storage Type Options

**1. `"memory"` (Default)**
- Uses SDK's standalone `InMemorySessionStorage`
- No external dependencies required
- Sessions stored in JavaScript `Map`
- Sessions lost on server restart
- Suitable for development or single-instance deployments

```bash
export SESSION_STORAGE_TYPE=memory
```

**2. `"express"` or `"express-session"`**
- Uses `express-session` compatible stores
- Requires `express-session` to be installed
- Defaults to `express-session` MemoryStore
- Can be overridden with `setExpressSessionStore()` for Redis, SQLite, etc.
- Suitable for main with persistent storage

```bash
export SESSION_STORAGE_TYPE=express-session
```

#### Configuring Persistent Storage

**SQLite Example:**
```javascript
const session = require('express-session')
const SQLiteStore = require('connect-sqlite3')(session)
const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
// Configure BEFORE initializing RoditClient
const sessionStore = new SQLiteStore({
  db: 'sessions.db',
  dir: './data',
  table: 'sessions'
})
setExpressSessionStore(sessionStore)
// Now initialize client
const client = await RoditClient.create('server')
```

**Redis Example:**
```javascript
const session = require('express-session')
const RedisStore = require('connect-redis').default
const { createClient } = require('redis')
const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
})
await redisClient.connect()
const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'rodit:sess:',
  ttl: 86400
})
setExpressSessionStore(redisStore)
```

#### Session Configuration Variables

```bash
// Storage backend type
export SESSION_STORAGE_TYPE=express-session
// Cleanup interval (milliseconds) - how often to remove expired sessions
export SESSION_CLEANUP_INTERVAL=3600000  # 1 hour
// Token retention period (seconds) - how long to keep closed sessions
export SESSION_TOKEN_RETENTION_PERIOD=604800  # 7 days
// Validation cache TTL (milliseconds) - trades security for performance
// Lower = more secure but more storage lookups
// Higher = faster but longer window after logout where token may still work
// Set to 0 to disable caching (always check session state)
export SESSION_VALIDATION_CACHE_TTL=5000  # 5 seconds
```

**Session Validation Cache:**

The SDK caches token validation results to reduce storage lookups:

- **Enabled by default** with 5-second TTL
- **Trade-off**: Performance vs. security
- **After logout**: Cache is immediately invalidated for that session
- **Recommendation**: Keep default (5s) for most use cases
- **High security**: Set to `0` to disable caching

```javascript
// Get cache statistics
const sessionManager = roditClient.getSessionManager()
const cacheStats = sessionManager.getValidationCacheStats()
console.log('Cache stats:', cacheStats)
// Output: { totalEntries: 10, validEntries: 8, expiredEntries: 2, cacheTTL: 5000, cacheEnabled: true }
```

### Session Operations

```javascript
// Get session manager
const sessionManager = roditClient.getSessionManager()
// Get active session count
const activeCount = await sessionManager.getActiveSessionCount()
// Get storage information
const storageInfo = await sessionManager.getStorageInfo()
console.log('Storage type:', storageInfo.type)
console.log('Session count:', storageInfo.sessionCount)
// Enumerate sessions via storage
const allSessions = await sessionManager.storage.getAll()
// Or fallback using keys() + get()
const sessionIds = await sessionManager.storage.keys()
const sessions = []
REPEAT: for (const id of sessionIds) {
  const session = await sessionManager.storage.get(id)
  if (session) sessions.push(session)
}
// Check if token is invalidated
const isInvalidated = await sessionManager.isTokenInvalidated(jwtToken)
// Get detailed invalidation info
const invalidationInfo = await sessionManager.getTokenInvalidationInfo(jwtToken)
if (invalidationInfo) {
  console.log('Invalidation reason:', invalidationInfo.reason)
  console.log('Invalidated at:', invalidationInfo.invalidatedAt)
}
// Manually close a session
await sessionManager.closeSession(sessionId, 'admin_action')
// Run manual cleanup (removes expired sessions)
const cleanup = await sessionManager.runManualCleanup()
console.log(`Removed ${cleanup.removedSessionsCount} expired sessions`)
// Get validation cache statistics
const cacheStats = sessionManager.getValidationCacheStats()
console.log('Cache entries:', cacheStats.totalEntries)
console.log('Cache TTL:', cacheStats.cacheTTL)
```

### Session Lifecycle

1. **Login** - Session created, JWT token issued with session ID
2. **Active** - Token validated on each request, session last_accessed updated
3. **Logout** - Session closed, token invalidated, termination token issued
4. **Expiration** - Sessions expire when stored `expiresAt` is reached (`SESSION_TTL_SECONDS` from login, capped by passport `not_after`)
5. **Cleanup** - Expired sessions removed by automatic cleanup process

### Token Invalidation

The SDK validates tokens by checking session state:

```javascript
// Authentication middleware checks:
// 1. JWT signature validity
// 2. JWT expiration
// 3. Session exists and is active
// 4. Session not expired
// After logout, tokens are invalidated because:
// - Session status set to 'closed'
// - Subsequent requests fail authentication
```

## Configuration

### Configuration Priority

The SDK automatically configures itself from multiple sources with a clear priority hierarchy:

1. **Environment Variables** (Highest priority) - Direct `process.env` access
2. **Host Application Config** - Values from `config` package (with env mappings)
3. **SDK Fallback Defaults** - Built-in defaults from `configsdk.js`
4. **Provided Default Value** - Optional parameter to `config.get()`

**Example:**
```javascript
const config = roditClient.getConfig()
// Priority 1: Checks process.env.SESSION_STORAGE_TYPE
// Priority 2: Checks host config.get('SESSION_STORAGE_TYPE')
// Priority 3: Uses SDK default 'memory'
// Priority 4: Falls back to 'memory' if provided
const storageType = config.get('SESSION_STORAGE_TYPE', 'memory')
```

This ensures that:
- CI/CD environment variables always take precedence
- Host applications can override SDK defaults
- SDK provides sensible defaults for all settings
- Configuration is predictable and debuggable

### Automatic Configuration Loading

The SDK loads configuration from multiple sources:

1. **Environment Variables** - Direct environment access
2. **Configuration Files** - config/default.json, config/main.json, config/development.json
3. **Vault Credentials** - Main credential storage
4. **SDK Defaults** - Fallback values

### Environment Configuration: NODE_ENV and LOG_LEVEL

The SDK uses **two separate environment variables** for configuration, following Node.js ecosystem standards:

#### NODE_ENV - Environment Type & Security Behavior

Controls environment-specific behavior and security settings:

**Values:**
- `main` - Main branch deploy (strict security, no error details)
- `development` - Development branch deploy (relaxed security, detailed errors)
- `test` - Testing environment (allows bypasses for automated testing)

**Default:** `development`

**Controls:**
- ✅ Error detail exposure in API responses
- ✅ Peer public key requirement enforcement
- ✅ Webhook verification bypass (test mode only)
- ✅ Security-critical behavior

#### LOG_LEVEL - Logging Verbosity

Controls Winston logger verbosity independently from environment:

**Values:**
- `error` - Only errors
- `warn` - Warnings and errors
- `info` - Informational messages, warnings, and errors (recommended for main)
- `debug` - Detailed debugging information
- `trace` - Maximum verbosity with full traces

**Default:** `info`

**Controls:**
- ✅ Winston logger output level
- ✅ Debug payload logging
- ✅ Log verbosity only (not security)

#### Separation of Concerns

```javascript
// Environment detection (security)
const isMain = process.env.NODE_ENV === 'main'
const isDevelopment = process.env.NODE_ENV === 'development'
const isTest = process.env.NODE_ENV === 'test'
// Logging verbosity (independent)
const config = roditClient.getConfig()
const logLevel = config.get('LOG_LEVEL', 'info')
```

#### Configuration Examples

**Main (normal):**
```bash
export NODE_ENV=main
export LOG_LEVEL=info
// Results in:
// - Strict security enforcement
// - No error details in responses
// - Minimal logging output
```

**Main (troubleshooting):**
```bash
export NODE_ENV=main
export LOG_LEVEL=debug
// Results in:
// - Strict security enforcement (still main)
// - No error details in responses (still secure)
// - Verbose logging for debugging
```

**Development:**
```bash
export NODE_ENV=development
export LOG_LEVEL=debug
// Results in:
// - Relaxed security for development
// - Detailed error messages in responses
// - Verbose logging
```

**Testing:**
```bash
export NODE_ENV=test
export LOG_LEVEL=error
// Results in:
// - Test mode (allows bypasses)
// - Detailed error messages
// - Only errors logged (cleaner test output)
```

#### Behavior Matrix

| Scenario | NODE_ENV | LOG_LEVEL | Security | Error Details | Logging |
|----------|----------|-----------|----------|---------------|---------|
| Main | `main` | `info` | ✅ Strict | ❌ Hidden | Minimal |
| Main Debug | `main` | `debug` | ✅ Strict | ❌ Hidden | Verbose |
| Development | `development` | `debug` | ⚠️ Relaxed | ✅ Shown | Verbose |
| Testing | `test` | `error` | ⚠️ Bypass OK | ✅ Shown | Errors only |

### Vault-Based Configuration (main)

For main deployments, credentials are loaded from HashiCorp Vault:

```bash
// Environment variables for vault
export RODIT_NEAR_CREDENTIALS_SOURCE=vault
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
export SERVICE_NAME=your-service-name
export NEAR_CONTRACT_ID=discernible-io.near
```

### File-Based Configuration (Development)

For development, credentials can be loaded from files:

```bash
export RODIT_NEAR_CREDENTIALS_SOURCE=file
export CREDENTIALS_FILE_PATH=./credentials/rodit-credentials.json
```

### Accessing Configuration

```javascript
// Get complete RODiT configuration
const configObject = await roditClient.getConfigOwnRodit()
const metadata = configObject.own_rodit.metadata
// Access RODiT token metadata
const jwtDuration = metadata.jwt_duration;  // JWT expiration time
const maxRequests = metadata.max_requests;  // Rate limit
const maxRqWindow = metadata.maxrq_window;  // Rate limit window
const apiEndpoint = metadata.subjectuniqueidentifier_url;  // API URL
const webhookUrl = metadata.webhook_url;  // Webhook endpoint
// Parse permissioned routes
const permissionedRoutes = JSON.parse(metadata.permissioned_routes || '{}')
// Use SDK config for application settings
const config = roditClient.getConfig()
const logLevel = config.get('LOG_LEVEL', 'info')
const dbPath = config.get('API_DEFAULT_OPTIONS.DB_PATH')
```

### Dynamic Rate Limiting

```javascript
// Configure rate limiting from RODiT token
const configObject = await roditClient.getConfigOwnRodit()
const metadata = configObject.own_rodit.metadata
if (metadata.max_requests && metadata.maxrq_window) {
  const maxRequests = parseInt(metadata.max_requests)
  const windowSeconds = parseInt(metadata.maxrq_window)
  const rateLimiter = roditClient.getRateLimitMiddleware()
  app.use(rateLimiter(maxRequests, windowSeconds))
}
```

### Environment Variables

Complete list of SDK environment variables:

#### Core Configuration
```bash
// Service identification
export SERVICE_NAME=your-service-name
export API_VERSION=1.0.0
// Environment and logging
export NODE_ENV=main               # main, development, test
export LOG_LEVEL=info                # error, warn, info, debug, trace
```

#### Credentials and Authentication
```bash
// Credential source
export RODIT_NEAR_CREDENTIALS_SOURCE=vault  # vault, file, env
// Vault configuration (main)
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
export VAULT_TOKEN_TTL=3600
// File-based credentials (development)
export CREDENTIALS_FILEPATH=./credentials/rodit.json
// NEAR blockchain
export NEAR_CONTRACT_ID=discernible-io.near
export NEAR_RPC_URL=https://rpc.mainnet.fastnear.com
export NEAR_RPC_CACHE_TTL=5000       # milliseconds
```

#### Session Management
```bash
// Session storage configuration
export SESSION_STORAGE_TYPE=express-session     # memory, express, express-session
export SESSION_CLEANUP_INTERVAL=3600000         # milliseconds (1 hour)
export SESSION_TOKEN_RETENTION_PERIOD=604800    # seconds (7 days)
export SESSION_VALIDATION_CACHE_TTL=5000        # milliseconds (5 seconds)
```

#### Logging and Monitoring
```bash
// Loki logging
export LOKI_URL=https://loki.example.com:3100
export LOKI_BASIC_AUTH=username:password
export LOKI_TLS_SKIP_VERIFY=false    # true to skip TLS verification
```

#### Security Options
```bash
// Webhook configuration
export WEBHOOK_TLS_SKIP_VERIFY=false  # true to skip TLS verification
// Login mode control (see Login Mode section below)
export SECURITY_OPTIONS_LOGIN_MODE=partner  # partner, promiscuous, or p2p
// Security thresholds
export SECURITY_OPTIONS_LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY=0.80
export SECURITY_OPTIONS_THRESHOLD_VALIDATION_TYPE=0.10
export SECURITY_OPTIONS_DURATIONRAMP=0.85
export SECURITY_OPTIONS_SERVERORCLIENT=SERVER-INITIATED
export SECURITY_OPTIONS_SILENT_LOGIN_FAILURES=false
// Server session lifetime (seconds from login; SDK default 5200)
export SECURITY_OPTIONS_SESSION_TTL_SECONDS=5200
// Access-token fallback when passport jwt_duration is invalid
export SECURITY_OPTIONS_FALLBACK_JWT_DURATION=3600
```

#### Database Configuration
```bash
export API_DEFAULT_OPTIONS_DB_PATH=/app/data/database.sqlite
```

## Logging & Monitoring

### Structured Logging

The SDK provides comprehensive structured logging:

```javascript
const { logger } = require('@rodit/rodit-auth-be')
// Basic logging
logger.info('Operation completed', {
  component: 'UserService',
  operation: 'createUser',
  userId: '123',
  duration: 150
})
// Context-aware logging
logger.infoWithContext('Request processed', {
  component: 'API',
  method: 'POST',
  path: '/api/users',
  requestId: req.requestId,
  userId: req.user?.id,
  duration: Date.now() - req.startTime
})
// Error logging with metrics
logger.errorWithContext('Operation failed', {
  component: 'UserService',
  operation: 'createUser',
  requestId: req.requestId,
  error: error.message,
  stack: error.stack
}, error)
```

### Loki with the SDK (canonical)

Use this as the authoritative guide for configuring logging with the SDK.

#### Environment variables

```bash
export LOKI_URL=https://<your-loki-host>:3100
export LOKI_BASIC_AUTH="username:password"   # store in secrets
export LOKI_TLS_SKIP_VERIFY=true              # only for self-signed/test
export LOG_LEVEL=info
export SERVICE_NAME=clienttest-idc
```

These are already mapped in `config/custom-environment-variables.json`, so container/CI env vars will flow into the app.

#### How the SDK selects/configures the logger

- Default: JSON to stdout only (no Loki). Honors `LOG_LEVEL`, adds `service_name`.
- Main: Create a Winston logger with a `winston-loki` transport and inject it once: `logger.setLogger(customLogger)`.
- Access: `const { logger } = require('@rodit/rodit-auth-be')` or `roditClient.getLogger()` both delegate to the same facade.

#### Direct-to-Loki via winston-loki (recommended)

```javascript
const { logger } = require('@rodit/rodit-auth-be')
const winston = require('winston')
const LokiTransport = require('winston-loki')
const transports = [new winston.transports.Console({ format: winston.format.json() })]
if (process.env.LOKI_URL) {
  const lokiOptions = {
    host: process.env.LOKI_URL,
    basicAuth: process.env.LOKI_BASIC_AUTH, // Basic Auth for Loki
    labels: { app: process.env.SERVICE_NAME || 'clienttest-idc', component: 'rodit-sdk' },
    json: true,
    batching: true
  }
if ((process.env.LOKI_TLS_SKIP_VERIFY || '').toLowerCase() === 'true') {
  lokiOptions.ssl = { rejectUnauthorized: false }
}
transports.push(new LokiTransport(lokiOptions))
}
const customLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports
})
logger.setLogger(customLogger)
```

#### CI/CD notes

- `.github/workflows/deploy.yml` passes `LOKI_URL`, `LOKI_TLS_SKIP_VERIFY`, `LOKI_BASIC_AUTH` into the container; `src/app.js` config injects the transport at startup.
- Store `LOKI_BASIC_AUTH` in CI/CD secrets; never commit credentials.

#### Quick verification

 1) Start the app with `LOKI_URL` and `LOKI_BASIC_AUTH` set.
 2) Emit a test log: `logger.info('Loki test', { component: 'SmokeTest' })`.
 3) In Grafana Explore, query with `{app="clienttest-idc"}` and confirm logs.

## Performance Tracking

The SDK includes comprehensive performance tracking and metrics collection.

### Performance Service

```javascript
const performanceService = roditClient.getPerformanceService()
// Record incoming request
performanceService.recordRequest(req)
// Record custom metrics with labels
performanceService.recordMetric('operation_duration', 150, {
  operation: 'db_query',
  table: 'users',
  status: 'success'
})
// Record errors
performanceService.recordMetric('error_count', 1, {
  method: req.method,
  path: req.path,
  status: res.statusCode
})
// Get aggregated metrics
const metrics = performanceService.getMetrics()
console.log('Total requests:', metrics.totalRequests)
console.log('Error count:', metrics.errorCount)
console.log('Average response time:', metrics.avgResponseTime)
```

### Automatic Request Tracking

Integrate performance tracking into your middleware:

```javascript
// Performance monitoring middleware
app.use((req, res, next) => {
  req.startTime = Date.now()
  const performanceService = roditClient.getPerformanceService()
  if (performanceService) {
    performanceService.recordRequest(req)
  }
res.on('finish', () => {
  const duration = Date.now() - req.startTime
  if (performanceService) {
    // Record request duration
    performanceService.recordMetric('request_duration_ms', duration, {
      method: req.method,
      path: req.path,
      status: res.statusCode
    })
  // Record errors
  if (res.statusCode >= 400) {
    performanceService.recordMetric('error_count', 1, {
      method: req.method,
      path: req.path,
      status: res.statusCode
    })
}
}
})
next()
})
```

### Session Performance Metrics

Track session-related performance:

```javascript
const sessionManager = roditClient.getSessionManager()
// Get validation cache statistics
const cacheStats = sessionManager.getValidationCacheStats()
logger.info('Session cache performance', {
  component: 'SessionManager',
  totalEntries: cacheStats.totalEntries,
  validEntries: cacheStats.validEntries,
  expiredEntries: cacheStats.expiredEntries,
  cacheTTL: cacheStats.cacheTTL,
  cacheEnabled: cacheStats.cacheEnabled
})
// Get storage information
const storageInfo = await sessionManager.getStorageInfo()
logger.info('Session storage status', {
  component: 'SessionManager',
  storageType: storageInfo.type,
  sessionCount: storageInfo.sessionCount,
  timestamp: storageInfo.timestamp
})
```

### Custom Metrics

Record application-specific metrics:

```javascript
const performanceService = roditClient.getPerformanceService()
// Database operation timing
const dbStart = Date.now()
const result = await db.query('SELECT * FROM users')
const dbDuration = Date.now() - dbStart
performanceService.recordMetric('db_query_duration', dbDuration, {
  operation: 'select',
  table: 'users',
  rowCount: result.length
})
// External API call timing
const apiStart = Date.now()
const apiResponse = await fetch('https://api.example.com/data')
const apiDuration = Date.now() - apiStart
performanceService.recordMetric('external_api_duration', apiDuration, {
  endpoint: 'api.example.com',
  status: apiResponse.status,
  success: apiResponse.ok
})
// Business metrics
performanceService.recordMetric('user_action', 1, {
  action: 'comment_created',
  userId: req.user.id,
  timestamp: new Date().toISOString()
})
```

 ## Webhooks
 
 ### Overview

The SDK supports sending webhooks to multiple endpoints for important events. Webhook URLs are configured in the RODiT token metadata.

**Key Features:**
- **Custom Endpoints** - Send webhooks to any endpoint path (e.g., `/hooks/wake`, `/hooks/agent`, `/webhook`)
- **Non-blocking** - Webhooks sent asynchronously without blocking the main response
- **Error Resilient** - Webhook failures don't affect the main operation

Webhooks are configured in your RODiT token:

```json
{
"webhook_url": "https:
"webhook_cidr": "0.0.0.0/0"
}
```

### Sending Webhooks to Default Endpoint

Send webhooks to the default `/webhook` endpoint:

```javascript
// Get webhook handler from client
const roditClient = req.app.locals.roditClient
// Send webhook for an event
const webhookPayload = {
  event: 'comment_created',
  data: {
    id: comment.id,
    author: comment.author,
    timestamp: new Date().toISOString()
  },
isError: false
}
try {
  const result = await roditClient.sendWebhook(webhookPayload, req)
  if (result.success) {
    logger.info('Webhook sent successfully', {
      component: 'CRUDA',
      event: webhookPayload.event,
      requestId: req.requestId
    })
}
} catch (error) {
// Webhook failures don't crash the application
logger.warn('Webhook delivery failed', {
  component: 'CRUDA',
  event: webhookPayload.event,
  error: error.message,
  requestId: req.requestId
})
}
```

### Sending Webhooks to Custom Endpoints

Send webhooks to specific endpoints like `/hooks/wake` or `/hooks/agent`:

```javascript
const roditClient = req.app.locals.roditClient
const webhookPayload = {
  event: 'heartbeat_request',
  data: {
    timestamp: new Date().toISOString(),
    source: '/api/testhola'
  }
}
// Send to /hooks/wake endpoint (trigger immediate heartbeat)
await roditClient.sendWebhookToEndpoint(webhookPayload, '/hooks/wake', req)
// Send to /hooks/agent endpoint (run isolated agent task)
await roditClient.sendWebhookToEndpoint(webhookPayload, '/hooks/agent', req)
// Send to custom endpoint
await roditClient.sendWebhookToEndpoint(webhookPayload, '/hooks/custom', req)
```

### Convenience Methods for Common Endpoints

```javascript
const roditClient = req.app.locals.roditClient
const payload = {
  event: 'test_event',
  data: { timestamp: new Date().toISOString() }
}
// Send to /hooks/wake (heartbeat confirmation)
await roditClient.sendWakeHook(payload, req)
// Send to /hooks/agent (agent task confirmation)
await roditClient.sendAgentHook(payload, req)
```

### Webhook Endpoint Purposes

| Endpoint | Purpose | Use Case |
|----------|---------|----------|
| `/webhook` | Default webhook endpoint | General event notifications |
| `/hooks/wake` | Trigger immediate heartbeat | Enqueue system event for main session |
| `/hooks/agent` | Run isolated agent task | Execute background tasks with optional reply to messaging channels |

### Webhook Error Handling

```javascript
// Graceful webhook handling in CRUDA operations
const logAndSendWebhook = async (payload, req = null) => {
  try {
    const roditClient = req?.app?.locals?.roditClient
    if (!roditClient) {
      logger.warn('RoditClient not available, skipping webhook', {
        component: 'CRUDA',
        event: payload?.event
      })
    { success: false, error: 'RoditClient not available' }
  }
await roditClient.sendWebhook(payload, req)
} catch (error) {
// Log but don't throw - webhook failures shouldn't crash the app
logger.error('Webhook delivery failed', {
  component: 'CRUDA',
  event: payload?.event,
  error: error.message
})
{ success: false, error: error.message }
}
}
```

### Development/Testing Webhooks

The `/api/testhola` endpoint sends test webhooks in development mode (`NODE_ENV === 'development'`):

```json
{
  "event": "testhola_validation_success",
  "data": {
    "peerTokenId": "bcdfhjkmnpqr",
    "serverTokenId": "bcdfhjkmnpqr",
    "recipient": "MUNDO",
    "timestamp": "2026-04-24T14:30:00.000Z",
    "endpoint": "/api/testhola"
  }
}
```

**Use Case:** Test webhook delivery and signature validation during development without needing a main deployment.

## Advanced Usage

### Route Module Pattern

Create reusable route modules that access the shared RoditClient:

```javascript
// routes/protected.js
const express = require('express')
const { logger } = require('@rodit/rodit-auth-be')
const router = express.Router()
// Middleware that uses the shared client
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authentication service unavailable' })
  }
client.authenticate(req, res, next)
}
const authorize = (req, res, next) => {
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authentication service unavailable' })
  }
client.authorize(req, res, next)
}
// Protected route with full authentication and authorization
router.get('/data', authenticate, authorize, async (req, res) => {
  const startTime = Date.now()
  try {
    // Your business logic here
    const data = await processUserData(req.user.id)
    logger.infoWithContext('Data retrieved successfully', {
      component: 'ProtectedRoutes',
      method: 'getData',
      userId: req.user.id,
      requestId: req.requestId,
      duration: Date.now() - startTime
    })
  res.json({ data, requestId: req.requestId })
} catch (error) {
logger.errorWithContext('Failed to retrieve data', {
  component: 'ProtectedRoutes',
  method: 'getData',
  userId: req.user.id,
  requestId: req.requestId,
  duration: Date.now() - startTime,
  error: error.message
}, error)
res.status(500).json({
  error: 'Internal server error',
  requestId: req.requestId
})
}
})
module.exports = router
```

### Portal Authentication (Server-to-Server)

For server-to-server authentication (e.g., minting client tokens):

```javascript
// routes/signclient.js
const router = express.Router()
router.post('/signclient', authenticate, authorize, async (req, res) => {
  const { tobesignedValues, mintingfee, mintingfeeaccount } = req.body
  const client = req.app.locals.roditClient
  const logger = client.getLogger()
  try {
    // Validate requested permissions against server's permissions
    const configObject = await client.getConfigOwnRodit()
    const serverPermissions = JSON.parse(
    configObject.own_rodit.metadata.permissioned_routes || '{}'
    )
    const requestedPermissions = JSON.parse(
    tobesignedValues.permissioned_routes || '{}'
    )
    // Validate that all requested routes exist in server config
    // (Implementation details in actual code)
    // Authenticate to portal and mint client token
    const port = configObject.port || 8443
    const result = await client.login_portal(configObject, port)
    if (result.error) {
      res.status(500).json({
        error: 'Portal authentication failed',
        details: result.message,
        requestId: req.requestId
      })
  }
// Sign the client token via portal
const signedToken = await signPortalRodit(
port,
tobesignedValues,
mintingfee,
mintingfeeaccount,
client
)
res.json({
  signedToken,
  requestId: req.requestId
})
} catch (error) {
logger.errorWithContext('Client token minting failed', {
  component: 'SignClient',
  requestId: req.requestId,
  error: error.message
}, error)
res.status(500).json({
  error: 'Token minting failed',
  requestId: req.requestId
})
}
})
module.exports = router
```

### SignPortal URL Configuration

#### Overview

When performing server-to-server authentication with SignPortal (e.g., minting client tokens), the SDK automatically constructs the SignPortal URL from the `serviceprovider_id` field in your RODiT token metadata.

#### Smart Contract Name Format

The SignPortal URL is derived from the smart contract component (`sc=`) in your `serviceprovider_id`. The SDK supports two formats:

**Standard Format (3+ components):**
```
sc=<number>-<domain>-<tld>.near
```

Example:
```
serviceprovider_id: "bc=near.org;sc=10975-discernible-org.near;id=..."
```

Parsing:
- Split by `.`: `["10975-discernible-org", "near"]`
- Take first part: `10975-discernible-org`
- Split by `-`: `["10975", "discernible", "org"]`
- Extract domain: `discernible` (index 1)
- Extract TLD: `org` (index 2)
- **Result**: `https://signportal.discernible.org:8443`

**Alternative Format (2 components):**
```
sc=<domain>-<tld>.near
```

Example:
```
serviceprovider_id: "bc=near.org;sc=roditcorp-com.near;id=..."
```

Parsing:
- Split by `.`: `["roditcorp-com", "near"]`
- Take first part: `roditcorp-com`
- Split by `-`: `["roditcorp", "com"]`
- Extract domain: `roditcorp` (index 0)
- Extract TLD: `com` (index 1)
- **Result**: `https://signportal.roditcorp.com:8443`

#### serviceprovider_id Structure

The complete `serviceprovider_id` format:
```
bc=<blockchain>;sc=<smart-contract>;id=<identifier>[;id=<additional-id>]
```

Components:
- `bc=` - Blockchain identifier (e.g., `near.org`)
- `sc=` - Smart contract name (used to construct SignPortal URL)
- `id=` - One or more identifier components

Example:
```json
{
  "serviceprovider_id": "bc=near.org;sc=roditcorp-com.near;id=01K8QECHMKFVNWQ54PJ2W2GMA7;id=01K8QECHMM1214VMDHSH7JM6H8"
}
```

#### URL Construction Method

The SDK uses `roditClient.getPortalUrl(serviceProviderId, port)` to construct the SignPortal URL:

```javascript
const client = req.app.locals.roditClient
const configObject = await client.getConfigOwnRodit()
const serviceProviderId = configObject.own_rodit.metadata.serviceprovider_id
const portalPort = 8443
// Automatically constructs: https://signportal.<domain>.<tld>:8443
const portalUrl = client.getPortalUrl(serviceProviderId, portalPort)
```

#### Troubleshooting

**Error: "Failed to parse URL from " (empty string)**
- **Cause**: `serviceprovider_id` is empty or undefined in your RODiT configuration
- **Solution**: Verify your RODiT token has a valid `serviceprovider_id` field
- **Check**: Run `./infra/roditwallet.sh <private-key> <token-id>` to view token metadata

**Error: "Invalid serviceprovider_id format: missing sc= component"**
- **Cause**: The `serviceprovider_id` doesn't contain an `sc=` component
- **Solution**: Ensure your token includes the smart contract identifier
- **Format**: `bc=near.org;sc=<contract-name>.near;id=...`

**Error: "Invalid domain format in smart contract"**
- **Cause**: Smart contract name has fewer than 2 components when split by `-`
- **Solution**: Use format `<domain>-<tld>` or `<number>-<domain>-<tld>`
- **Valid**: `roditcorp-com.near`, `10975-discernible-org.near`
- **Invalid**: `roditcorp.near`, `mycontract.near`

#### Configuration Verification

To verify your SignPortal URL configuration:

```javascript
const client = req.app.locals.roditClient
const logger = client.getLogger()
try {
  const configObject = await client.getConfigOwnRodit()
  const serviceProviderId = configObject.own_rodit.metadata.serviceprovider_id
  logger.info('RODiT Configuration', {
    component: 'SignPortal',
    serviceProviderId,
    hasServiceProviderId: !!serviceProviderId
  })
if (serviceProviderId) {
  const portalUrl = client.getPortalUrl(serviceProviderId, 8443)
  logger.info('SignPortal URL constructed', {
    component: 'SignPortal',
    portalUrl
  })
}
} catch (error) {
logger.error('SignPortal URL construction failed', {
  component: 'SignPortal',
  error: error.message
})
}
```

### CRUDA Operations Example

Complete CRUD implementation with authentication, authorization, webhooks, and performance tracking:

```javascript
// protected/cruda.js
const express = require('express')
const router = express.Router()
const { RoditClient } = require('@rodit/rodit-auth-be')
const sqlite3 = require('sqlite3')
const { open } = require('sqlite')
const { ulid } = require('ulid')
const sdkClient = new RoditClient()
const logger = sdkClient.getLogger()
let db
// Initialize database
const initializeDatabase = async () => {
  const db = await open({
    filename: '/app/data/database.sqlite',
    driver: sqlite3.Database
  })
await db.run(`CREATE TABLE IF NOT EXISTS comments (
id INTEGER PRIMARY KEY AUTOINCREMENT,
comment TEXT NOT NULL,
author TEXT,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`)
}
// Webhook helper
const logAndSendWebhook = async (payload, req) => {
  try {
    const roditClient = req?.app?.locals?.roditClient
    if (!roditClient) return { success: false }
    await roditClient.send_webhook(payload, req)
  } catch (error) {
  logger.error('Webhook failed', { error: error.message })
  { success: false, error: error.message }
}
}
// CREATE
router.post('/create', async (req, res) => {
  const { comment, author } = req.body
  const requestId = req.requestId || ulid()
  try {
    const result = await db.run(
    'INSERT INTO comments (comment, author) VALUES (?, ?)',
    [comment, author || req.user.roditId]
    )
    // Send webhook
    await logAndSendWebhook({
      event: 'comment_created',
      data: { id: result.lastID, comment, author },
      isError: false
    }, req)
  res.json({ id: result.lastID, requestId })
} catch (error) {
logger.errorWithContext('Create failed', {
  component: 'CRUDA',
  error: error.message,
  requestId
}, error)
res.status(500).json({ error: 'Create failed', requestId })
}
})
// LIST
router.post('/list', async (req, res) => {
  try {
    const records = await db.all(
    'SELECT * FROM comments ORDER BY created_at DESC'
    )
    res.json({ records, requestId: req.requestId })
  } catch (error) {
  res.status(500).json({ error: 'List failed', requestId: req.requestId })
}
})
// READ
router.post('/read', async (req, res) => {
  const { id } = req.body
  try {
    const record = await db.get('SELECT * FROM comments WHERE id = ?', [id])
    if (!record) {
      res.status(404).json({ error: 'Not found', requestId: req.requestId })
    }
  res.json({ record, requestId: req.requestId })
} catch (error) {
res.status(500).json({ error: 'Read failed', requestId: req.requestId })
}
})
// UPDATE
router.post('/update', async (req, res) => {
  const { id, comment } = req.body
  try {
    await db.run(
    'UPDATE comments SET comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [comment, id]
    )
    await logAndSendWebhook({
      event: 'comment_updated',
      data: { id, comment },
      isError: false
    }, req)
  res.json({ success: true, requestId: req.requestId })
} catch (error) {
res.status(500).json({ error: 'Update failed', requestId: req.requestId })
}
})
// DELETE
router.post('/destroy', async (req, res) => {
  const { id } = req.body
  try {
    await db.run('DELETE FROM comments WHERE id = ?', [id])
    await logAndSendWebhook({
      event: 'comment_deleted',
      data: { id },
      isError: false
    }, req)
  res.json({ success: true, requestId: req.requestId })
} catch (error) {
res.status(500).json({ error: 'Delete failed', requestId: req.requestId })
}
})
// Export initialization function
module.exports = router
module.exports.initializeDatabase = initializeDatabase
```

## API Reference

### RoditClient Class

The main client class for all RODiT operations.

#### Static Methods

##### RoditClient.create(role)

Create and initialize a RODiT client in one step.

```javascript
const client = await RoditClient.create('server');  // For server applications
const client = await RoditClient.create('client');  // For client applications
const client = await RoditClient.create('portal');  // For portal authentication
```

**Parameters:**
- `role` (string): Client role - `'server'`, `'client'`, or `'portal'`

**Returns:** `Promise<RoditClient>` - Fully initialized client instance

**Throws:** Error if initialization fails (e.g., missing credentials, Vault connection failure)

#### Instance Methods

##### authenticate(req, res, next)

Express middleware for authenticating API requests. Validates JWT tokens and populates `req.user`.

```javascript
const authenticate = (req, res, next) => roditClient.authenticate(req, res, next)
app.use('/api/protected', authenticate, handler)
```

**Validates:**
- JWT signature
- JWT expiration
- Session exists and is active
- Token not invalidated
- Canonical JWT base64url encoding (header/payload/signature)

**Populates:** `req.user` with decoded JWT claims

##### authenticateForLogout(req, res, next)

Express middleware for logout routes. It validates signature and claims like normal auth, but allows
signature-valid expired JWT tokens so sessions can still be closed safely.

```javascript
const authenticateLogout = (req, res, next) => roditClient.authenticateForLogout(req, res, next)
app.post('/api/logout', authenticateLogout, (req, res) => roditClient.logout_client(req, res))
```

**Use case:** clean logout when token is expired but cryptographically valid.

##### authorize(req, res, next)

Express middleware for validating route permissions. Must be used after `authenticate`.

```javascript
const authorize = (req, res, next) => roditClient.authorize(req, res, next)
app.use('/api/admin', authenticate, authorize, handler)
```

**Validates:** User has permission for the requested route and HTTP method

##### login_client(req, res)

Handle Express login requests from clients. Validates RODiT credentials and issues JWT token.

```javascript
app.post('/api/login', (req, res) => roditClient.login_client(req, res))
```

**Request Body:** `login_client` accepts `accountid`, `timestamp`, and `base64url_signature`.

**Response:**
```javascript
{
  jwt_token: '<jwt-token>',
  requestId: '01HQXYZ...'
}
```

##### logout_client(req, res)

Handle Express logout requests. Closes session and invalidates JWT token.

```javascript
const authenticateLogout = (req, res, next) => roditClient.authenticateForLogout(req, res, next)
app.post('/api/logout', authenticateLogout, (req, res) => {
  roditClient.logout_client(req, res)
})
```

**Response:**
```javascript
{
  message: 'Logout successful',
  terminationToken: '<jwt-token>',  // Short-lived token
  requestId: '01HQXYZ...'
}
```

##### login_portal(configObject, port)

Authenticate to RODiT portal for server-to-server operations using account-based login payloads.

```javascript
const configObject = await roditClient.getConfigOwnRodit()
const result = await roditClient.login_portal(configObject, 8443)
```

**Returns:** `Promise<Object>` - Portal authentication result

##### login_server(options)

Authenticate to a peer API (home or federated). Signs **`roditid`** or **`accountid`** + canonical `timestamp_iso` and POSTs the login body expected by the peer's `login_client`.

**Options:**

| Option | Description |
|--------|-------------|
| `apiEndpoint` | Federated (or override) API base URL. Defaults to own `subjectuniqueidentifier_url`. MITM-checked via JWT `rodit_subjectuniqueidentifier_url` when it differs from client home. |
| `loginPath` | HTTP path (default `/api/login`) |
| `timestamp` | Unix seconds; if omitted, fetched from peer `GET /api/login/timestamp` |
| `accountId` | NEAR account when signing without `own_rodit.token_id` |
| `timestampPath` | Timestamp path (default `/api/login/timestamp`) |

```javascript
// Same-API (home)
const home = await roditClient.login_server();

// Federated login into a sibling API in the same family
const fed = await roditClient.login_server({
  apiEndpoint: 'https://api-b.example.com',
  loginPath: '/api/login', // optional
});
```

**Returns:** `Promise<Object>` - Authentication result with `jwt_token`, or `{ error, errorCode, failureReason, requestId }` on failure (`FEDERATED_ISSUER_MISSING` / `FEDERATED_ISSUER_MISMATCH` for MITM failures).

##### logout_server()

Logout from server-to-server session.

```javascript
const result = await roditClient.logout_server()
```

**Returns:** `Promise<Object>` - Logout result with session closure status

##### getConfigOwnRodit()

Get the complete RODiT configuration including token metadata.

```javascript
const configObject = await roditClient.getConfigOwnRodit()
const metadata = configObject.own_rodit.metadata
const tokenId = configObject.own_rodit.token_id
```

**Returns:** `Promise<Object>` - Complete RODiT configuration

**Structure:**
```javascript
{
  own_rodit: {
    token_id: string,
    metadata: {
      jwt_duration: number,
      max_requests: string,
      maxrq_window: string,
      permissioned_routes: string,  // JSON string
      subjectuniqueidentifier_url: string,
      webhook_url: string,
      // ... other metadata fields
    }
},
port: number
}
```

##### isOperationPermitted(method, path)

Check if an operation is permitted based on token permissions.

```javascript
const hasPermission = roditClient.isOperationPermitted('POST', '/api/admin/users')
if (!hasPermission) {
  res.status(403).json({ error: 'Forbidden' })
}
```

**Parameters:**
- `method` (string): HTTP method
- `path` (string): API path

**Returns:** `boolean`

##### getStateManager()

Get the authentication state manager.

```javascript
const stateManager = roditClient.getStateManager()
```

**Returns:** `AuthStateManager` instance

##### getRoditManager()

Get the RODiT manager for credential operations.

```javascript
const roditManager = roditClient.getRoditManager()
const credentials = await roditManager.getCredentials('server')
```

**Returns:** `RoditManager` instance

##### getSessionManager()

Get the session manager.

```javascript
const sessionManager = roditClient.getSessionManager()
const activeCount = await sessionManager.getActiveSessionCount()
```

**Returns:** `SessionManager` instance

##### getLogger()

Get the logger instance.

```javascript
const logger = roditClient.getLogger()
logger.info('Message', { component: 'MyComponent' })
```

**Returns:** `Logger` instance

##### getLoggingMiddleware()

Get the logging middleware.

```javascript
const loggingmw = roditClient.getLoggingMiddleware()
app.use(loggingmw)
```

**Returns:** Express middleware function

##### getRateLimitMiddleware()

Get the rate limiting middleware factory.

```javascript
const ratelimitmw = roditClient.getRateLimitMiddleware()
const limiter = ratelimitmw(100, 900);  // 100 requests per 15 minutes
app.use(limiter)
```

**Parameters:**
- `maxRequests` (number): Maximum requests allowed
- `windowSeconds` (number): Time window in seconds

**Returns:** Express middleware function

##### getPerformanceService()

Get the performance tracking service.

```javascript
const performanceService = roditClient.getPerformanceService()
performanceService.recordRequest(req)
performanceService.recordMetric('operation_duration', 150, { operation: 'db_query' })
```

**Returns:** `PerformanceService` instance

##### getConfig()

Get the configuration service.

```javascript
const config = roditClient.getConfig()
const dbPath = config.get('API_DEFAULT_OPTIONS.DB_PATH')
```

**Returns:** `Config` instance

##### getWebhookHandler()

Get the webhook handler.

```javascript
const webhookHandler = roditClient.getWebhookHandler()
```

**Returns:** `WebhookHandler` instance

##### send_webhook(payload, req)

Send a webhook notification.

```javascript
const result = await roditClient.send_webhook({
  event: 'user_action',
  data: { userId: '123', action: 'login' },
  isError: false
}, req)
```

**Parameters:**
- `payload` (Object): Webhook payload
  - `event` (string): Event name
  - `data` (Object): Event data
  - `isError` (boolean): Whether this is an error event
- `req` (Object): Express request object (optional)

**Returns:** `Promise<Object>` - `{ success: boolean, ... }`

### Exported Components

The SDK exports these components for direct use:

```javascript
const {
  RoditClient,           // Main client class
  logger,                // Logger instance
  stateManager,          // Authentication state manager
  roditManager,          // RODiT credential manager
  sessionManager,        // Session manager instance
  blockchainService,     // Blockchain operations
  utils,                 // Utility functions
  config,                // Configuration service
  performanceService,    // Performance tracking
  authenticate_apicall,  // Authentication middleware
  authenticate_logout,   // Logout authentication middleware (expired-token tolerant)
  login_client,          // Login handler
  logout_client,         // Logout handler
  login_client_withnep413, // NEP-413 login
  login_portal,          // Portal authentication
  login_server,          // Outbound peer login
  logout_server,         // Server logout
  validate_jwt_token_be, // JWT validation
  generate_jwt_token,    // JWT generation
  normalizeUrlWithoutPort,     // URL compare helper (strip port)
  isNonEmptyUrlClaim,          // federated claim present & non-empty
  isFederatedRoditLogin,       // peer vs own subject URL differs
  validateFederatedLoginTarget, // client MITM check after JWT crypto
  validatepermissions,   // Permission middleware
  webhookHandler,        // Webhook handler
  versioningMiddleware,  // API versioning
  loggingmw,             // Logging middleware
  ratelimitmw,           // Rate limiting middleware
  versionManager,        // Version manager
  VersionManager,        // Version manager class
  nearorg_rpc_timestamp  // Blockchain RPC timestamp function
} = require('@rodit/rodit-auth-be')
// Note: Session storage configuration functions are available via:
// const { setExpressSessionStore, configureStorageFromConfig,
  // InMemorySessionStorage }
// = require('@rodit/rodit-auth-be/lib/auth/sessionmanager');
```

### RODiT Token Metadata Fields

When you call `roditClient.getConfigOwnRodit()`, you get access to these metadata fields:

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string | Unique RODiT token identifier |
| `allowed_cidr` | string | Permitted IP address ranges (CIDR format) |
| `allowed_iso3166list` | string | Geographic restrictions (JSON string) |
| `jwt_duration` | number | Access JWT credential lifetime in seconds (renewed until `session_exp`; does not set server session length when `SESSION_TTL_SECONDS` is configured) |
| `max_requests` | string | Rate limit - maximum requests per window |
| `maxrq_window` | string | Rate limit - time window in seconds |
| `not_before` | string | Token validity start date (ISO format) |
| `not_after` | string | Token validity end date (ISO format) |
| `openapijson_url` | string | OpenAPI specification URL |
| `permissioned_routes` | string | Allowed API routes and methods (JSON string) |
| `serviceprovider_id` | string | Blockchain contract and service provider info |
| `serviceprovider_signature` | string | Cryptographic signature for verification |
| `subjectuniqueidentifier_url` | string | Primary API service endpoint |
| `userselected_dn` | string | User-selected display name |
| `webhook_cidr` | string | Allowed IP ranges for webhooks |
| `webhook_url` | string | Webhook endpoint URL |

## Best Practices

### 1. Single Client Initialization

Always initialize the RoditClient once in your main application file:

```javascript
// ✅ Good - Single initialization
async function startServer() {
  const roditClient = await RoditClient.create('server')
  app.locals.roditClient = roditClient
  // Mount protected routes AFTER client initialization
  const authenticate = (req, res, next) => roditClient.authenticate(req, res, next)
  const authorize = (req, res, next) => roditClient.authorize(req, res, next)
  app.use('/api/echo', authenticate, echoRoutes)
  app.use('/api/cruda', authenticate, authorize, crudaRoutes)
  // ... rest of server setup
}
// ❌ Bad - Multiple initializations
app.get('/route1', async (req, res) => {
  const client = await RoditClient.create('server'); // Don't do this
})
```

### 2. Use App.locals for Shared Access

Store the client in `app.locals` for access across all routes:

```javascript
// ✅ Good - Shared instance via app.locals
const router = express.Router()
router.get('/data', (req, res) => {
  const client = req.app.locals.roditClient
  const logger = client.getLogger()
  logger.info('Processing request', {
    component: 'DataRoute',
    userId: req.user?.id,
    requestId: req.requestId
  })
res.json({ data: 'example' })
})
// ❌ Bad - Creating new instances in routes
const { RoditClient } = require('@rodit/rodit-auth-be')
const client = new RoditClient(); // Don't do this in routes
```

### 3. Proper Error Handling

Always wrap SDK operations in try-catch blocks and include request context:

```javascript
// ✅ Good - Comprehensive error handling
app.get('/api/data', authenticate, async (req, res) => {
  const startTime = Date.now()
  const client = req.app.locals.roditClient
  const logger = client.getLogger()
  try {
    const data = await processData(req.user.id)
    logger.infoWithContext('Request successful', {
      component: 'API',
      method: 'getData',
      userId: req.user.id,
      requestId: req.requestId,
      duration: Date.now() - startTime
    })
  res.json({ data, requestId: req.requestId })
} catch (error) {
logger.errorWithContext('Request failed', {
  component: 'API',
  method: 'getData',
  userId: req.user.id,
  requestId: req.requestId,
  duration: Date.now() - startTime,
  error: error.message
}, error)
res.status(500).json({
  error: 'Internal server error',
  requestId: req.requestId
})
}
})
```

### 4. Structured Logging

Use consistent logging patterns with context:

```javascript
// ✅ Good - Structured logging with context
const logger = req.app.locals.roditClient.getLogger()
logger.infoWithContext('User action completed', {
  component: 'UserService',
  action: 'updateProfile',
  userId: user.id,
  requestId: req.requestId,
  duration: Date.now() - startTime,
  changes: Object.keys(updates)
})
// For errors, pass the error object
logger.errorWithContext('Operation failed', {
  component: 'UserService',
  action: 'updateProfile',
  userId: user.id,
  requestId: req.requestId,
  error: error.message
}, error)
// ❌ Bad - Unstructured logging
console.log('User updated profile'); // Don't do this
```

### 5. Environment-Specific Configuration

Use environment variables for sensitive and environment-specific values:

```javascript
// ✅ Good - Environment-aware configuration
const config = roditClient.getConfig()
const logLevel = config.get('LOG_LEVEL', 'info')
const isMainDeploy = ['info', 'warn', 'error'].includes(logLevel)
// Main should use vault credentials
if (isMainDeploy && process.env.RODIT_NEAR_CREDENTIALS_SOURCE !== 'vault') {
  logger.warn('Main environment should use vault credentials', {
    component: 'Configuration',
    environment: 'main',
    credentialsSource: process.env.RODIT_NEAR_CREDENTIALS_SOURCE || 'not-set'
  })
}
// Configure session storage before initializing client
if (isMainDeploy) {
  const SQLiteStore = require('connect-sqlite3')(require('express-session'))
  const sessionStore = new SQLiteStore({
    db: 'sessions.db',
    dir: config.get('API_DEFAULT_OPTIONS.DB_PATH', './data')
  })
setExpressSessionStore(sessionStore)
}
```

### 6. Graceful Shutdown

Implement proper shutdown handling:

```javascript
// ✅ Good - Graceful shutdown
const shutdown = async (signal) => {
  const logger = roditClient.getLogger()
  logger.info('Shutting down gracefully', {
    component: 'AppLifecycle',
    signal: signal || 'unknown',
    time: new Date().toISOString()
  })
if (server) {
  server.close(async () => {
    logger.info('HTTP server closed')
    // Close database connections
    if (db && typeof db.close === 'function') {
      await db.close()
      logger.info('Database connections closed')
    }
  // Close session store
  if (sessionStore && typeof sessionStore.close === 'function') {
    await new Promise((resolve) => sessionStore.close(resolve))
    logger.info('Session store closed')
  }
process.exit(0)
})
// Force shutdown after timeout
setTimeout(() => {
  logger.error('Forced shutdown after timeout')
  process.exit(1)
}, 10000)
}
}
process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))
```

### 7. Request Context and Performance Tracking

Always include request context and track performance:

```javascript
// ✅ Good - Request context and performance tracking
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || ulid()
  req.startTime = Date.now()
  next()
})
// Performance monitoring
app.use((req, res, next) => {
  const performanceService = roditClient.getPerformanceService()
  if (performanceService) {
    performanceService.recordRequest(req)
  }
res.on('finish', () => {
  const duration = Date.now() - req.startTime
  if (performanceService) {
    performanceService.recordMetric('request_duration_ms', duration, {
      method: req.method,
      path: req.path,
      status: res.statusCode
    })
  if (res.statusCode >= 400) {
    performanceService.recordMetric('error_count', 1, {
      method: req.method,
      path: req.path,
      status: res.statusCode
    })
}
}
})
next()
})
```

### 8. Login Endpoint Protection

**CRITICAL:** Never protect the login endpoint with authentication middleware:

```javascript
// ✅ Good - Login endpoint without authentication
app.post('/api/login', (req, res) => {
  req.logAction = 'login-attempt'
  roditClient.login_client(req, res)
})
// ❌ Bad - Login endpoint with authentication (creates circular dependency)
app.post('/api/login', authenticate, (req, res) => {  // DON'T DO THIS
  roditClient.login_client(req, res)
})
// ✅ Better - Logout endpoint with logout-specific authentication
const authenticateLogout = (req, res, next) => roditClient.authenticateForLogout(req, res, next)
app.post('/api/logout', authenticateLogout, (req, res) => {
  req.logAction = 'logout-attempt'
  roditClient.logout_client(req, res)
})
```

### 9. Route Mounting Order

Mount protected routes AFTER client initialization:

```javascript
// ✅ Good - Correct order
async function startServer() {
  // 1. Configure session storage
  setExpressSessionStore(sessionStore)
  // 2. Initialize client
  const roditClient = await RoditClient.create('server')
  app.locals.roditClient = roditClient
  // 3. Create middleware
  const authenticate = (req, res, next) => roditClient.authenticate(req, res, next)
  const authenticateLogout = (req, res, next) => roditClient.authenticateForLogout(req, res, next)
  const authorize = (req, res, next) => roditClient.authorize(req, res, next)
  // 4. Mount public routes
  app.post('/api/login', loginRoute)
  // 5. Mount protected routes
  app.use('/api/echo', authenticate, echoRoutes)
  app.use('/api/cruda', authenticate, authorize, crudaRoutes)
  app.post('/api/logout', authenticateLogout, logoutRoute)
  // 6. Start server
  app.listen(port)
}
// ❌ Bad - Routes mounted before client initialization
app.use('/api/echo', authenticate, echoRoutes);  // authenticate is undefined!
const roditClient = await RoditClient.create('server')
```

## Troubleshooting

### Common Issues

#### 1. Authentication Middleware Errors

**Problem:** `roditClient.authenticate is not a function` or `Cannot read properties of undefined`

**Solution:** Ensure client is initialized and stored in app.locals:
```javascript
// ✅ Correct - Check client availability
const authenticate = (req, res, next) => {
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ error: 'Authentication service unavailable' })
  }
client.authenticate(req, res, next)
}
// ❌ Wrong - Direct access without checking
const authenticate = (req, res, next) => roditClient.authenticate(req, res, next)
// This fails if roditClient is not initialized yet
```

#### 2. Configuration Not Found

**Problem:** `Failed to initialize RODiT configuration`

**Solutions:**
```bash
// Check environment variables
echo $RODIT_NEAR_CREDENTIALS_SOURCE  # Should be 'vault' or 'file'
echo $VAULT_ENDPOINT
echo $NEAR_CONTRACT_ID
echo $SERVICE_NAME
// For vault-based credentials
export RODIT_NEAR_CREDENTIALS_SOURCE=vault
export VAULT_ENDPOINT=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
// For file-based credentials (development)
export RODIT_NEAR_CREDENTIALS_SOURCE=file
export CREDENTIALS_FILE_PATH=./credentials/rodit-credentials.json
```

**Verify configuration:**
```javascript
const config = roditClient.getConfig()
console.log('NEAR_CONTRACT_ID:', config.get('NEAR_CONTRACT_ID'))
console.log('SERVICE_NAME:', config.get('SERVICE_NAME'))
```

#### 3. Missing App.locals Client

**Problem:** `RoditClient not available in app.locals` or `Cannot read properties of undefined (reading 'roditClient')`

**Solution:** Ensure client is stored during initialization:
```javascript
async function startServer() {
  try {
    // Initialize client
    const roditClient = await RoditClient.create('server')
    // Store in app.locals BEFORE mounting routes
    app.locals.roditClient = roditClient
    // Verify it's stored
    if (!app.locals.roditClient) {
      throw new Error('Failed to store roditClient in app.locals')
    }
  // Now mount routes
  const authenticate = (req, res, next) => roditClient.authenticate(req, res, next)
  app.use('/api/protected', authenticate, protectedRoutes)
  app.listen(port)
} catch (error) {
console.error('Server initialization failed:', error)
process.exit(1)
}
}
```

#### 4. Permission Denied Errors

**Problem:** Routes return 403 Forbidden

**Debug steps:**
```javascript
// Check token permissions
const configObject = await roditClient.getConfigOwnRodit()
const permissionedRoutes = JSON.parse(
configObject.own_rodit.metadata.permissioned_routes || '{}'
)
console.log('Configured permissions:', permissionedRoutes)
// Check specific operation
const hasPermission = roditClient.isOperationPermitted('POST', '/api/cruda/create')
console.log('Has permission:', hasPermission)
// Verify route path matches exactly
console.log('Requested path:', req.path);  // Must match permission key exactly
```

**Common issues:**
- Route path doesn't match permission key exactly (e.g., `/api/cruda/create` vs `/cruda/create`)
- HTTP method not allowed in permission configuration
- Permission format incorrect (should be `"+0"` for all methods)
- Client token has different permissions than server token

#### 5. Session Not Found Errors

**Problem:** `401 Unauthorized - session_not_found`

**Cause:** JWT token contains session ID that doesn't exist in session storage

**Solutions:**
```javascript
// Verify session storage is configured
const sessionManager = roditClient.getSessionManager()
const storageInfo = await sessionManager.getStorageInfo()
console.log('Storage type:', storageInfo.storageType)
console.log('Active sessions:', storageInfo.sessionCount)
// Check if token is invalidated
const isInvalidated = await sessionManager.isTokenInvalidated(jwtToken)
console.log('Token invalidated:', isInvalidated)
// Enumerate sessions via storage for debugging
const allSessions = await sessionManager.storage.getAll()
console.log('Active sessions:', allSessions.filter(s => s.status === 'active').length)
```

**Common causes:**
- Server restarted with in-memory storage (sessions lost)
- Session expired
- Token was invalidated by logout
- Session storage not configured properly

**Solution:** Use persistent storage (SQLite or Redis) for main

#### 6. Logging Issues

**Problem:** Logs not appearing in Loki or console

**Solutions:**
```bash
// Check logging configuration
export LOG_LEVEL=debug  # Enable debug logging
export LOKI_URL=https://loki.example.com:3100
export LOKI_BASIC_AUTH=username:password
```

```javascript
// Test logger directly
const logger = roditClient.getLogger()
logger.info('Test message', { component: 'Test' })
logger.error('Test error', { component: 'Test' })
// Check if Loki transport is configured
const transports = logger.transports
console.log('Logger transports:', transports.map(t => t.name))
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
export LOG_LEVEL=debug  # Use 'debug' or 'trace' for development mode
```

This will provide detailed information about:
- Authentication flows and token validation
- Configuration loading from Vault/files
- Permission checks and route matching
- Session creation and validation
- Network requests to portal/blockchain
- Internal SDK operations
- Request/response details

**Example debug output:**
```javascript
const logger = roditClient.getLogger()
// Enable debug logging programmatically
logger.level = 'debug'
// Debug authentication
logger.debug('Authenticating request', {
  component: 'Authentication',
  hasAuthHeader: !!req.headers.authorization,
  path: req.path,
  method: req.method
})
```

### Health Checks

Implement comprehensive health check endpoints:

```javascript
app.get('/health', async (req, res) => {
  try {
    const client = req.app.locals.roditClient
    if (!client) {
      res.status(503).json({
        status: 'error',
        message: 'RoditClient not available'
      })
  }
const configObject = await client.getConfigOwnRodit()
const sessionManager = client.getSessionManager()
const performanceService = client.getPerformanceService()
const health = {
  status: 'healthy',
  timestamp: new Date().toISOString(),
  logLevel: config.get('LOG_LEVEL', 'info'),
  components: {
    roditClient: !!client,
    configuration: !!(configObject && configObject.own_rodit),
    sessionManager: !!sessionManager,
    performanceService: !!performanceService
  },
metrics: {
  activeSessions: await sessionManager.getActiveSessionCount(),
  totalRequests: performanceService.getRequestCount(),
  errorCount: performanceService.getErrorCount()
},
roditToken: {
  tokenId: configObject?.own_rodit?.token_id,
  apiUrl: configObject?.own_rodit?.metadata?.subjectuniqueidentifier_url,
  jwtDuration: configObject?.own_rodit?.metadata?.jwt_duration
}
}
res.json(health)
} catch (error) {
res.status(503).json({
  status: 'error',
  message: error.message,
  timestamp: new Date().toISOString()
})
}
})
// Readiness check (for Kubernetes)
app.get('/ready', async (req, res) => {
  const client = req.app.locals.roditClient
  if (!client) {
    res.status(503).json({ ready: false })
  }
try {
  const configObject = await client.getConfigOwnRodit()
  const ready = !!(configObject && configObject.own_rodit)
  res.status(ready ? 200 : 503).json({ ready })
} catch (error) {
res.status(503).json({ ready: false, error: error.message })
}
})
// Liveness check (for Kubernetes)
app.get('/live', (req, res) => {
  res.json({ alive: true })
})
```

### Support

For additional support:
1. Check the debug logs with `LOG_LEVEL=debug`
2. Verify your RODiT token configuration
3. Test with the health check endpoint
4. Review the authentication flow in the logs
5. Ensure all required environment variables are set

---

## License

Copyright (c) 2026 Discernible IO. All rights reserved.
