# RODiT Authentication SDK

A comprehensive Node.js SDK for implementing RODiT-based mutual authentication, authorization, self-configuration, and session management in Express.js applications.

**Version:** 1.1.0  
**License:** Proprietary  
**Author:** Discernible IO

**Login `POST` /api/login:** Use **`accountid`**, **`timestamp`**, and **`base64url_signature`**. Sign UTF-8 bytes of `accountid + timestamp_iso`, and reject deprecated keys such as **`signature`** and **`account_id`**. See [CHANGELOG.md](./CHANGELOG.md).

## Table of Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Installation & Setup](#installation--setup)
- [Authentication](#authentication)
  - [Login Mode Control](#login-mode-control)
- [Authorization & Permissions](#authorization--permissions)
- [Session Management](#session-management)
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - RUN COMMAND: npm install @rodit/rodit-auth-be
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Basic Server Setup

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET express TO require('express')
  - DO: const { RoditClient } = require('@rodit/rodit-auth-be')
  - DO: const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
  - DO: const { ulid } = require('ulid')
  - SET session TO require('express-session')
  - SET SQLiteStore TO require('connect-sqlite3')(session)
  - SET app TO express()
  - DO: let roditClient
  - NOTE: Configure session storage BEFORE initializing RoditClient
  - SET sessionStore TO new SQLiteStore({
  - FIELD: db: 'sessions.db',
  - FIELD: dir: './data',
  - FIELD: table: 'sessions'
  - DO: })
  - DO: setExpressSessionStore(sessionStore)
  - NOTE: Configure Express middleware
  - DO: app.use(express.json())
  - FIELD: app.use(express.urlencoded({ extended: false }))
  - NOTE: Request context middleware
  - DO: app.use((req, res, next) => {
  - DO: req.requestId = req.headers['x-request-id'] || ulid()
  - DO: req.startTime = Date.now()
  - DO: next()
  - DO: })
  - NOTE: Server startup with SDK initialization
  - DO: async function startServer() {
  - DO: try {
  - NOTE: Initialize RODiT client (use 'server' for server applications)
  - SET roditClient TO await RoditClient.create('server')
  - NOTE: Store client in app.locals for route access
  - DO: app.locals.roditClient = roditClient
  - NOTE: Get logger and other services from client
  - SET logger TO roditClient.getLogger()
  - SET config TO roditClient.getConfig()
  - SET loggingmw TO roditClient.getLoggingMiddleware()
  - NOTE: Apply logging middleware
  - DO: app.use(loggingmw)
  - NOTE: Create authentication middleware
  - SET authenticate TO (req, res, next) => roditClient.authenticate(req, res, next)
  - NOTE: Logout-specific auth allows signature-valid expired tokens for clean session closure
  - SET authenticateLogout TO (req, res, next) => roditClient.authenticateForLogout(req, res, next)
  - SET authorize TO (req, res, next) => roditClient.authorize(req, res, next)
  - NOTE: Public routes
  - DO: app.post('/api/login', (req, res) => {
  - DO: req.logAction = 'login-attempt'
  - RETURN roditClient.login_client(req, res)
  - DO: })
  - NOTE: Protected routes
  - DO: app.post('/api/logout', authenticateLogout, (req, res) => {
  - DO: req.logAction = 'logout-attempt'
  - RETURN roditClient.logout_client(req, res)
  - DO: })
  - DO: app.get('/api/protected', authenticate, (req, res) => {
  - FIELD: res.json({ message: 'Protected data', user: req.user })
  - DO: })
  - NOTE: Protected + authorized routes
  - DO: app.use('/api/admin', authenticate, authorize, adminRoutes)
  - SET port TO 3000
  - DO: app.listen(port, () => {
  - DO: logger.info(`RODiT Authentication Server running on port ${port}`)
  - DO: })
  - DO: } catch (error) {
  - FIELD: console.error('Server initialization failed:', error)
  - DO: process.exit(1)
  - }
  - }
  - DO: startServer()
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: In main app.js
  - SET roditClient TO await RoditClient.create('server')
  - DO: app.locals.roditClient = roditClient
  - NOTE: In route modules
  - SET router TO express.Router()
  - DO: router.get('/data', (req, res) => {
  - SET client TO req.app.locals.roditClient
  - SET logger TO client.getLogger()
  - DO: logger.info('Processing request', {
  - FIELD: component: 'DataRoute',
  - FIELD: userId: req.user?.id
  - DO: })
  - FIELD: res.json({ data: 'example' })
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Authentication Middleware Pattern

Create middleware functions that delegate to the RoditClient:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Create reusable middleware
  - SET authenticate TO (req, res, next) => {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authentication service unavailable' })
  - }
  - RETURN client.authenticate(req, res, next)
  - DO: }
  - SET authorize TO (req, res, next) => {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authorization service unavailable' })
  - }
  - RETURN client.authorize(req, res, next)
  - DO: }
  - NOTE: Use in routes
  - DO: app.get('/api/protected', authenticate, handler)
  - DO: app.post('/api/admin', authenticate, authorize, adminHandler)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

## Installation & Setup

### Dependencies

**Required:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - RUN COMMAND: npm install @rodit/rodit-auth-be express config winston
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Recommended for main:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - RUN COMMAND: npm install express-session connect-sqlite3
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Optional:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - RUN COMMAND: npm install node-vault  # For Vault-based credentials
  - RUN COMMAND: npm install winston-loki  # For Grafana Loki logging
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Environment Variables

**Vault Configuration (main):**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export RODIT_NEAR_CREDENTIALS_SOURCE=vault
  - FIELD: export VAULT_ENDPOINT=https://vault.example.com
  - DO: export VAULT_ROLE_ID=your-role-id
  - DO: export VAULT_SECRET_ID=your-secret-id
  - DO: export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
  - DO: export SERVICE_NAME=your-service-name
  - DO: export NEAR_CONTRACT_ID=rodit.near
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Application Configuration:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - FIELD: export NODE_ENV=main  # Environment: main, development, test
  - FIELD: export LOG_LEVEL=info       # Logging: error, warn, info, debug, trace
  - DO: export API_DEFAULT_OPTIONS_DB_PATH=/app/data/database.sqlite
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Session Configuration:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - FIELD: export SESSION_STORAGE_TYPE=express-session  # Storage: memory, express, express-session
  - DO: export SESSION_CLEANUP_INTERVAL=3600000      # Cleanup interval in milliseconds (1 hour)
  - DO: export SESSION_TOKEN_RETENTION_PERIOD=604800 # Token retention in seconds (7 days)
  - DO: export SESSION_VALIDATION_CACHE_TTL=5000     # Cache TTL in milliseconds (5 seconds)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Logging Configuration:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - FIELD: export LOKI_URL=https://loki.example.com:3100
  - FIELD: export LOKI_BASIC_AUTH=username:password
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Configuration Files

Create `config/default.json`:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: "NEAR_CONTRACT_ID": "rodit.near",
  - FIELD: "SERVICE_NAME": "your-service",
  - FIELD: "SECURITY_OPTIONS": {
  - FIELD: "SILENT_LOGIN_FAILURES": false,
  - FIELD: "FALLBACK_JWT_DURATION": 3600  // SECURITY_OPTIONS.FALLBACK_JWT_DURATION — when metadata jwt_duration is invalid
  - }
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Implicit account login
  - {
  - FIELD: "accountid": "<64-char-hex>",
  - FIELD: "timestamp": 1640995200,
  - FIELD: "base64url_signature": "base64url-encoded-signature"
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

Use **`base64url_signature`** in login payloads for API login examples.

Rejected keys (HTTP 400, `LOGIN_PAYLOAD_DEPRECATED`): **`signature`** and **`account_id`**.

#### Server Response

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Success (200)
  - {
  - FIELD: "jwt_token": "<jwt-token>",
  - FIELD: "requestId": "01HQXYZ123ABC"
  - }
  - NOTE: Headers:
  - NOTE: New-Token: <jwt>   (same token echoed for header-based clients)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Authentication Flow

1. **Client sends RODiT credentials** - RODiT ID, timestamp, and cryptographic signature
2. **SDK verifies signature** - Validates against blockchain records (NEAR Protocol)
3. **Session created** - New session stored in session manager
4. **JWT token issued** - Token contains session ID and user claims
5. **Subsequent requests** - Client sends JWT in `Authorization: Bearer <token>` header
6. **Token validation** - SDK validates JWT and checks session status

Security hardening in current implementation:
- JWT compact parts must be canonical base64url (non-canonical encodings are rejected).
- Session registration is enforced during JWT validation (unknown/inactive/expired sessions are rejected).
- Token renewal uses `sessionManager` for session checks and updates (no `stateManager` session mutations).

### Login Implementation

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: routes/login.js
  - SET express TO require('express')
  - SET router TO express.Router()
  - DO: router.post('/login', async (req, res) => {
  - DO: req.logAction = 'login-attempt'
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authentication service unavailable' })
  - }
  - NOTE: Delegate to SDK's login_client method
  - WAIT FOR: client.login_client(req, res)
  - DO: })
  - DO: module.exports = router
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Logout Implementation

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Logout invalidates the JWT token and closes the session
  - NOTE: Use logout-specific auth so signature-valid expired tokens can still logout.
  - DO: router.post('/logout', authenticateLogout, async (req, res) => {
  - DO: req.logAction = 'logout-attempt'
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authentication service unavailable' })
  - }
  - NOTE: Delegate to SDK's logout_client method
  - WAIT FOR: client.logout_client(req, res)
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Protected Routes

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Require authentication for access
  - DO: app.get('/api/data', authenticate, (req, res) => {
  - NOTE: req.user contains authenticated user information
  - SET logger TO req.app.locals.roditClient.getLogger()
  - DO: logger.info('Protected route accessed', {
  - FIELD: component: 'API',
  - FIELD: userId: req.user.id,
  - FIELD: roditId: req.user.roditId,
  - FIELD: requestId: req.requestId
  - DO: })
  - DO: res.json({
  - FIELD: message: 'Authenticated data',
  - FIELD: user: req.user,
  - FIELD: requestId: req.requestId
  - DO: })
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Authentication Middleware

The `authenticate` middleware validates JWT tokens and populates `req.user`:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET authenticate TO (req, res, next) => {
  - SET client TO req.app.locals.roditClient
  - RETURN client.authenticate(req, res, next)
  - DO: }
  - NOTE: After successful authentication, req.user contains:
  - NOTE: {
  - NOTE: id: 'user-unique-id',
  - NOTE: roditId: '01K4G3D95QF6NR0RSJK9WEK6KA',
  - NOTE: aud: 'audience',
  - NOTE: iss: 'issuer',
  - NOTE: exp: 1640999999,
  - NOTE: iat: 1640995200,
  - NOTE: session_id: '01HQXYZ123ABC'
  - NOTE: }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: No configuration needed - this is the default
  - NOTE: Only client-server authentication is accepted
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Accept All Logins:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export SECURITY_OPTIONS_LOGIN_MODE=promiscuous
  - NOTE: Both Partner and Peer logins are accepted
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Peer-to-Peer Only:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export SECURITY_OPTIONS_LOGIN_MODE=p2p
  - NOTE: Only peer-to-peer authentication is accepted
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Docker/Podman:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: podman run -e SECURITY_OPTIONS_LOGIN_MODE=partner ...
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**GitHub Actions:**
Add repository variable:
- **Name**: `SECURITY_OPTIONS_LOGIN_MODE`
- **Value**: `partner` | `promiscuous` | `p2p`

#### Logging and Monitoring

**Successful Login:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: "level": "info",
  - FIELD: "message": "PARTNER login verified successfully",
  - FIELD: "verificationType": "PARTNER",
  - FIELD: "loginMode": "partner",
  - FIELD: "duration": 1234
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Rejected Login:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: "level": "warn",
  - FIELD: "message": "PEER login rejected by LOGIN_MODE policy",
  - FIELD: "verificationType": "PEER",
  - FIELD: "loginMode": "partner",
  - FIELD: "policyReason": "LOGIN_MODE=partner does not accept PEER logins"
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Metrics:**
- `rodit_match_verification` with `result: "success"` - Successful authentication
- `rodit_match_verification` with `result: "policy_rejected"` - Rejected by policy

#### Security Considerations

1. **Default is Secure**: The default `partner` mode provides the most restrictive access control
2. **Promiscuous Mode**: Use only when you need to accept both types of authentication
3. **P2P Mode**: Use when building peer-to-peer systems where only same-provider authentication is needed
4. **Policy Enforcement**: Rejections are logged with clear reasons for audit trails

#### Troubleshooting

**Login Rejected with "policy_rejected":**
- If you see "PEER login rejected" and need to accept peer logins, set mode to `promiscuous` or `p2p`
- If you see "PARTNER login rejected" and need to accept partner logins, set mode to `promiscuous` or `partner`

**Check Current Mode:**
Look for the log message during authentication:
```
"Starting RODiT match verification" with "loginMode": "partner"
```

## Authorization & Permissions

### Route-Based Permissions

Permissions are configured in your RODiT token metadata using the `permissioned_routes` field:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: "permissioned_routes": {
  - FIELD: "entities": {
  - FIELD: "/": {
  - FIELD: "methods": "+0"
  - DO: },
  - FIELD: "/api/echo": {
  - FIELD: "methods": "+0"
  - DO: },
  - FIELD: "/api/cruda/create": {
  - FIELD: "methods": "+0"
  - DO: },
  - FIELD: "/api/cruda/list": {
  - FIELD: "methods": "+0"
  - DO: },
  - FIELD: "/api/admin": {
  - FIELD: "methods": "+0"
  - }
  - }
  - }
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Permission Format:**
- `"+0"` = All methods allowed (GET, POST, PUT, DELETE, etc.)
- `"+1"` = GET only
- `"+2"` = POST only
- Custom combinations can be defined

### Permission Validation Middleware

The `authorize` middleware validates that the authenticated user has permission to access the requested route:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET authenticate TO (req, res, next) => {
  - RETURN req.app.locals.roditClient.authenticate(req, res, next)
  - DO: }
  - SET authorize TO (req, res, next) => {
  - RETURN req.app.locals.roditClient.authorize(req, res, next)
  - DO: }
  - NOTE: Apply both authentication and authorization
  - DO: app.use('/api/admin', authenticate, authorize, adminRoutes)
  - NOTE: CRUDA endpoints with full protection
  - DO: app.use('/api/cruda', authenticate, authorize, crudaRoutes)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Permission Enforcement

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Example: CRUDA routes with permission checking
  - SET router TO express.Router()
  - NOTE: All routes require authentication + authorization
  - DO: router.post('/create', async (req, res) => {
  - NOTE: User must have permission for POST /api/cruda/create
  - DO: const { comment, author } = req.body
  - NOTE: Create record in database
  - SET result TO await db.run(
  - DO: 'INSERT INTO comments (comment, author) VALUES (?, ?)',
  - DO: [comment, author || req.user.roditId]
  - DO: )
  - FIELD: res.json({ id: result.lastID, requestId: req.requestId })
  - DO: })
  - DO: router.post('/list', async (req, res) => {
  - NOTE: User must have permission for POST /api/cruda/list
  - SET records TO await db.all('SELECT * FROM comments ORDER BY created_at DESC')
  - FIELD: res.json({ records, requestId: req.requestId })
  - DO: })
  - DO: module.exports = router
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Dynamic Permission Checking

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Check permissions programmatically
  - SET client TO req.app.locals.roditClient
  - SET hasPermission TO client.isOperationPermitted('POST', '/api/admin/users')
  - CHECK CONDITION: if (!hasPermission) {
  - RETURN res.status(403).json({
  - FIELD: error: 'Forbidden',
  - FIELD: message: 'You do not have permission to access this resource',
  - FIELD: requestId: req.requestId
  - DO: })
  - }
  - NOTE: Proceed with operation
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Permission Validation in Client Token Minting

When minting client tokens via `/api/signclient`, the server validates that requested permissions are a subset of the server's own permissions:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Client requests these permissions:
  - SET requestedPermissions TO {
  - FIELD: "/": "+0",
  - FIELD: "/api/echo": "+0",
  - FIELD: "/api/cruda/create": "+0"
  - DO: }
  - NOTE: Server validates against its own permissioned_routes
  - NOTE: If any requested route is not in server's config, request is rejected with HTTP 400
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

## Session Management

### Overview

The SDK includes a comprehensive session management system that:
- Tracks active user sessions
- Validates JWT tokens against session state
- Supports pluggable storage backends
- Automatically cleans up expired sessions
- Integrates with performance metrics

### Session Storage Backends

#### 1. In-Memory Storage (Default)

No configuration needed - works out of the box:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET client TO await RoditClient.create('server')
  - NOTE: Uses InMemorySessionStorage by default
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Pros:** Fast, zero configuration  
**Cons:** Sessions lost on server restart, not suitable for multi-server deployments

#### 2. SQLite Storage (Recommended for main)

Persistent storage using SQLite database:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET express TO require('express')
  - SET session TO require('express-session')
  - SET SQLiteStore TO require('connect-sqlite3')(session)
  - DO: const { RoditClient } = require('@rodit/rodit-auth-be')
  - DO: const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
  - NOTE: Configure BEFORE initializing RoditClient
  - SET sessionStore TO new SQLiteStore({
  - FIELD: db: 'sessions.db',
  - FIELD: dir: './data',
  - FIELD: table: 'sessions'
  - DO: })
  - DO: setExpressSessionStore(sessionStore)
  - NOTE: Now initialize client
  - SET client TO await RoditClient.create('server')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Pros:** Persistent across restarts, simple setup, uses existing database infrastructure  
**Cons:** Not suitable for multi-server deployments

#### 3. Redis Storage (For Multi-Server)

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - RUN COMMAND: npm install express-session connect-redis redis
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET session TO require('express-session')
  - SET RedisStore TO require('connect-redis').default
  - DO: const { createClient } = require('redis')
  - DO: const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
  - NOTE: Create Redis client
  - SET redisClient TO createClient({
  - FIELD: url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
  - DO: })
  - WAIT FOR: redisClient.connect()
  - NOTE: Create Redis store
  - SET redisStore TO new RedisStore({
  - FIELD: client: redisClient,
  - FIELD: prefix: 'rodit:sess:',
  - FIELD: ttl: 86400 // 24 hours
  - DO: })
  - DO: setExpressSessionStore(redisStore)
  - SET client TO await RoditClient.create('server')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export SESSION_STORAGE_TYPE=memory
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**2. `"express"` or `"express-session"`**
- Uses `express-session` compatible stores
- Requires `express-session` to be installed
- Defaults to `express-session` MemoryStore
- Can be overridden with `setExpressSessionStore()` for Redis, SQLite, etc.
- Suitable for main with persistent storage

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export SESSION_STORAGE_TYPE=express-session
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Configuring Persistent Storage

**SQLite Example:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET session TO require('express-session')
  - SET SQLiteStore TO require('connect-sqlite3')(session)
  - DO: const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
  - NOTE: Configure BEFORE initializing RoditClient
  - SET sessionStore TO new SQLiteStore({
  - FIELD: db: 'sessions.db',
  - FIELD: dir: './data',
  - FIELD: table: 'sessions'
  - DO: })
  - DO: setExpressSessionStore(sessionStore)
  - NOTE: Now initialize client
  - SET client TO await RoditClient.create('server')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Redis Example:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET session TO require('express-session')
  - SET RedisStore TO require('connect-redis').default
  - DO: const { createClient } = require('redis')
  - DO: const { setExpressSessionStore } = require('@rodit/rodit-auth-be/lib/auth/sessionmanager')
  - SET redisClient TO createClient({
  - FIELD: url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
  - DO: })
  - WAIT FOR: redisClient.connect()
  - SET redisStore TO new RedisStore({
  - FIELD: client: redisClient,
  - FIELD: prefix: 'rodit:sess:',
  - FIELD: ttl: 86400
  - DO: })
  - DO: setExpressSessionStore(redisStore)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Session Configuration Variables

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Storage backend type
  - DO: export SESSION_STORAGE_TYPE=express-session
  - NOTE: Cleanup interval (milliseconds) - how often to remove expired sessions
  - DO: export SESSION_CLEANUP_INTERVAL=3600000  # 1 hour
  - NOTE: Token retention period (seconds) - how long to keep closed sessions
  - DO: export SESSION_TOKEN_RETENTION_PERIOD=604800  # 7 days
  - NOTE: Validation cache TTL (milliseconds) - trades security for performance
  - NOTE: Lower = more secure but more storage lookups
  - NOTE: Higher = faster but longer window after logout where token may still work
  - NOTE: Set to 0 to disable caching (always check session state)
  - DO: export SESSION_VALIDATION_CACHE_TTL=5000  # 5 seconds
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Session Validation Cache:**

The SDK caches token validation results to reduce storage lookups:

- **Enabled by default** with 5-second TTL
- **Trade-off**: Performance vs. security
- **After logout**: Cache is immediately invalidated for that session
- **Recommendation**: Keep default (5s) for most use cases
- **High security**: Set to `0` to disable caching

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Get cache statistics
  - SET sessionManager TO roditClient.getSessionManager()
  - SET cacheStats TO sessionManager.getValidationCacheStats()
  - FIELD: console.log('Cache stats:', cacheStats)
  - NOTE: Output: { totalEntries: 10, validEntries: 8, expiredEntries: 2, cacheTTL: 5000, cacheEnabled: true }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Session Operations

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Get session manager
  - SET sessionManager TO roditClient.getSessionManager()
  - NOTE: Get active session count
  - SET activeCount TO await sessionManager.getActiveSessionCount()
  - NOTE: Get storage information
  - SET storageInfo TO await sessionManager.getStorageInfo()
  - FIELD: console.log('Storage type:', storageInfo.type)
  - FIELD: console.log('Session count:', storageInfo.sessionCount)
  - NOTE: Enumerate sessions via storage
  - SET allSessions TO await sessionManager.storage.getAll()
  - NOTE: Or fallback using keys() + get()
  - SET sessionIds TO await sessionManager.storage.keys()
  - SET sessions TO []
  - REPEAT: for (const id of sessionIds) {
  - SET session TO await sessionManager.storage.get(id)
  - CHECK CONDITION: if (session) sessions.push(session)
  - }
  - NOTE: Check if token is invalidated
  - SET isInvalidated TO await sessionManager.isTokenInvalidated(jwtToken)
  - NOTE: Get detailed invalidation info
  - SET invalidationInfo TO await sessionManager.getTokenInvalidationInfo(jwtToken)
  - CHECK CONDITION: if (invalidationInfo) {
  - FIELD: console.log('Invalidation reason:', invalidationInfo.reason)
  - FIELD: console.log('Invalidated at:', invalidationInfo.invalidatedAt)
  - }
  - NOTE: Manually close a session
  - WAIT FOR: sessionManager.closeSession(sessionId, 'admin_action')
  - NOTE: Run manual cleanup (removes expired sessions)
  - SET cleanup TO await sessionManager.runManualCleanup()
  - DO: console.log(`Removed ${cleanup.removedSessionsCount} expired sessions`)
  - NOTE: Get validation cache statistics
  - SET cacheStats TO sessionManager.getValidationCacheStats()
  - FIELD: console.log('Cache entries:', cacheStats.totalEntries)
  - FIELD: console.log('Cache TTL:', cacheStats.cacheTTL)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Session Lifecycle

1. **Login** - Session created, JWT token issued with session ID
2. **Active** - Token validated on each request, session last_accessed updated
3. **Logout** - Session closed, token invalidated, termination token issued
4. **Expiration** - Sessions automatically expire based on JWT duration
5. **Cleanup** - Expired sessions removed by automatic cleanup process

### Token Invalidation

The SDK validates tokens by checking session state:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Authentication middleware checks:
  - NOTE: 1. JWT signature validity
  - NOTE: 2. JWT expiration
  - NOTE: 3. Session exists and is active
  - NOTE: 4. Session not expired
  - NOTE: After logout, tokens are invalidated because:
  - NOTE: - Session status set to 'closed'
  - NOTE: - Subsequent requests fail authentication
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

## Configuration

### Configuration Priority

The SDK automatically configures itself from multiple sources with a clear priority hierarchy:

1. **Environment Variables** (Highest priority) - Direct `process.env` access
2. **Host Application Config** - Values from `config` package (with env mappings)
3. **SDK Fallback Defaults** - Built-in defaults from `configsdk.js`
4. **Provided Default Value** - Optional parameter to `config.get()`

**Example:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET config TO roditClient.getConfig()
  - NOTE: Priority 1: Checks process.env.SESSION_STORAGE_TYPE
  - NOTE: Priority 2: Checks host config.get('SESSION_STORAGE_TYPE')
  - NOTE: Priority 3: Uses SDK default 'memory'
  - NOTE: Priority 4: Falls back to 'memory' if provided
  - SET storageType TO config.get('SESSION_STORAGE_TYPE', 'memory')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Environment detection (security)
  - SET isMain TO process.env.NODE_ENV === 'main'
  - SET isDevelopment TO process.env.NODE_ENV === 'development'
  - SET isTest TO process.env.NODE_ENV === 'test'
  - NOTE: Logging verbosity (independent)
  - SET config TO roditClient.getConfig()
  - SET logLevel TO config.get('LOG_LEVEL', 'info')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Configuration Examples

**Main (normal):**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export NODE_ENV=main
  - DO: export LOG_LEVEL=info
  - NOTE: Results in:
  - NOTE: - Strict security enforcement
  - NOTE: - No error details in responses
  - NOTE: - Minimal logging output
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Main (troubleshooting):**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export NODE_ENV=main
  - DO: export LOG_LEVEL=debug
  - NOTE: Results in:
  - NOTE: - Strict security enforcement (still main)
  - NOTE: - No error details in responses (still secure)
  - NOTE: - Verbose logging for debugging
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Development:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export NODE_ENV=development
  - DO: export LOG_LEVEL=debug
  - NOTE: Results in:
  - NOTE: - Relaxed security for development
  - NOTE: - Detailed error messages in responses
  - NOTE: - Verbose logging
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Testing:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export NODE_ENV=test
  - DO: export LOG_LEVEL=error
  - NOTE: Results in:
  - NOTE: - Test mode (allows bypasses)
  - NOTE: - Detailed error messages
  - NOTE: - Only errors logged (cleaner test output)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Environment variables for vault
  - DO: export RODIT_NEAR_CREDENTIALS_SOURCE=vault
  - FIELD: export VAULT_ENDPOINT=https://vault.example.com
  - DO: export VAULT_ROLE_ID=your-role-id
  - DO: export VAULT_SECRET_ID=your-secret-id
  - DO: export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
  - DO: export SERVICE_NAME=your-service-name
  - DO: export NEAR_CONTRACT_ID=rodit.near
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### File-Based Configuration (Development)

For development, credentials can be loaded from files:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export RODIT_NEAR_CREDENTIALS_SOURCE=file
  - DO: export CREDENTIALS_FILE_PATH=./credentials/rodit-credentials.json
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Accessing Configuration

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Get complete RODiT configuration
  - SET configObject TO await roditClient.getConfigOwnRodit()
  - SET metadata TO configObject.own_rodit.metadata
  - NOTE: Access RODiT token metadata
  - SET jwtDuration TO metadata.jwt_duration;  // JWT expiration time
  - SET maxRequests TO metadata.max_requests;  // Rate limit
  - SET maxRqWindow TO metadata.maxrq_window;  // Rate limit window
  - SET apiEndpoint TO metadata.subjectuniqueidentifier_url;  // API URL
  - SET webhookUrl TO metadata.webhook_url;  // Webhook endpoint
  - NOTE: Parse permissioned routes
  - SET permissionedRoutes TO JSON.parse(metadata.permissioned_routes || '{}')
  - NOTE: Use SDK config for application settings
  - SET config TO roditClient.getConfig()
  - SET logLevel TO config.get('LOG_LEVEL', 'info')
  - SET dbPath TO config.get('API_DEFAULT_OPTIONS.DB_PATH')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Dynamic Rate Limiting

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Configure rate limiting from RODiT token
  - SET configObject TO await roditClient.getConfigOwnRodit()
  - SET metadata TO configObject.own_rodit.metadata
  - CHECK CONDITION: if (metadata.max_requests && metadata.maxrq_window) {
  - SET maxRequests TO parseInt(metadata.max_requests)
  - SET windowSeconds TO parseInt(metadata.maxrq_window)
  - SET rateLimiter TO roditClient.getRateLimitMiddleware()
  - DO: app.use(rateLimiter(maxRequests, windowSeconds))
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Environment Variables

Complete list of SDK environment variables:

#### Core Configuration
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Service identification
  - DO: export SERVICE_NAME=your-service-name
  - DO: export API_VERSION=1.0.0
  - NOTE: Environment and logging
  - DO: export NODE_ENV=main               # main, development, test
  - DO: export LOG_LEVEL=info                # error, warn, info, debug, trace
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Credentials and Authentication
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Credential source
  - DO: export RODIT_NEAR_CREDENTIALS_SOURCE=vault  # vault, file, env
  - NOTE: Vault configuration (main)
  - FIELD: export VAULT_ENDPOINT=https://vault.example.com
  - DO: export VAULT_ROLE_ID=your-role-id
  - DO: export VAULT_SECRET_ID=your-secret-id
  - DO: export VAULT_RODIT_KEYVALUE_PATH=secret/rodit
  - DO: export VAULT_TOKEN_TTL=3600
  - NOTE: File-based credentials (development)
  - DO: export CREDENTIALS_FILEPATH=./credentials/rodit.json
  - NOTE: NEAR blockchain
  - DO: export NEAR_CONTRACT_ID=rodit.near
  - FIELD: export NEAR_RPC_URL=https://rpc.mainnet.fastnear.com
  - DO: export NEAR_RPC_CACHE_TTL=5000       # milliseconds
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Session Management
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Session storage configuration
  - DO: export SESSION_STORAGE_TYPE=express-session     # memory, express, express-session
  - DO: export SESSION_CLEANUP_INTERVAL=3600000         # milliseconds (1 hour)
  - DO: export SESSION_TOKEN_RETENTION_PERIOD=604800    # seconds (7 days)
  - DO: export SESSION_VALIDATION_CACHE_TTL=5000        # milliseconds (5 seconds)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Logging and Monitoring
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Loki logging
  - FIELD: export LOKI_URL=https://loki.example.com:3100
  - FIELD: export LOKI_BASIC_AUTH=username:password
  - DO: export LOKI_TLS_SKIP_VERIFY=false    # true to skip TLS verification
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Security Options
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Webhook configuration
  - DO: export WEBHOOK_TLS_SKIP_VERIFY=false  # true to skip TLS verification
  - NOTE: Login mode control (see Login Mode section below)
  - DO: export SECURITY_OPTIONS_LOGIN_MODE=partner  # partner, promiscuous, or p2p
  - NOTE: Security thresholds
  - DO: export SECURITY_OPTIONS_LAPSED_LIFETIME_PROPORTION_4RENEWAL_ELIGIBILITY=0.80
  - DO: export SECURITY_OPTIONS_THRESHOLD_VALIDATION_TYPE=0.10
  - DO: export SECURITY_OPTIONS_DURATIONRAMP=0.85
  - DO: export SECURITY_OPTIONS_SERVERORCLIENT=SERVER-INITIATED
  - DO: export SECURITY_OPTIONS_SILENT_LOGIN_FAILURES=false
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### Database Configuration
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export API_DEFAULT_OPTIONS_DB_PATH=/app/data/database.sqlite
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

## Logging & Monitoring

### Structured Logging

The SDK provides comprehensive structured logging:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: const { logger } = require('@rodit/rodit-auth-be')
  - NOTE: Basic logging
  - DO: logger.info('Operation completed', {
  - FIELD: component: 'UserService',
  - FIELD: operation: 'createUser',
  - FIELD: userId: '123',
  - FIELD: duration: 150
  - DO: })
  - NOTE: Context-aware logging
  - DO: logger.infoWithContext('Request processed', {
  - FIELD: component: 'API',
  - FIELD: method: 'POST',
  - FIELD: path: '/api/users',
  - FIELD: requestId: req.requestId,
  - FIELD: userId: req.user?.id,
  - FIELD: duration: Date.now() - req.startTime
  - DO: })
  - NOTE: Error logging with metrics
  - DO: logger.errorWithContext('Operation failed', {
  - FIELD: component: 'UserService',
  - FIELD: operation: 'createUser',
  - FIELD: requestId: req.requestId,
  - FIELD: error: error.message,
  - FIELD: stack: error.stack
  - DO: }, error)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Loki with the SDK (canonical)

Use this as the authoritative guide for configuring logging with the SDK.

#### Environment variables

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - FIELD: export LOKI_URL=https://<your-loki-host>:3100
  - FIELD: export LOKI_BASIC_AUTH="username:password"   # store in secrets
  - DO: export LOKI_TLS_SKIP_VERIFY=true              # only for self-signed/test
  - DO: export LOG_LEVEL=info
  - DO: export SERVICE_NAME=clienttest-idc
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

These are already mapped in `config/custom-environment-variables.json`, so container/CI env vars will flow into the app.

#### How the SDK selects/configures the logger

- Default: JSON to stdout only (no Loki). Honors `LOG_LEVEL`, adds `service_name`.
- Main: Create a Winston logger with a `winston-loki` transport and inject it once: `logger.setLogger(customLogger)`.
- Access: `const { logger } = require('@rodit/rodit-auth-be')` or `roditClient.getLogger()` both delegate to the same facade.

#### Direct-to-Loki via winston-loki (recommended)

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: const { logger } = require('@rodit/rodit-auth-be')
  - SET winston TO require('winston')
  - SET LokiTransport TO require('winston-loki')
  - SET transports TO [new winston.transports.Console({ format: winston.format.json() })]
  - CHECK CONDITION: if (process.env.LOKI_URL) {
  - SET lokiOptions TO {
  - FIELD: host: process.env.LOKI_URL,
  - FIELD: basicAuth: process.env.LOKI_BASIC_AUTH, // Basic Auth for Loki
  - FIELD: labels: { app: process.env.SERVICE_NAME || 'clienttest-idc', component: 'rodit-sdk' },
  - FIELD: json: true,
  - FIELD: batching: true
  - DO: }
  - CHECK CONDITION: if ((process.env.LOKI_TLS_SKIP_VERIFY || '').toLowerCase() === 'true') {
  - FIELD: lokiOptions.ssl = { rejectUnauthorized: false }
  - }
  - DO: transports.push(new LokiTransport(lokiOptions))
  - }
  - SET customLogger TO winston.createLogger({
  - FIELD: level: process.env.LOG_LEVEL || 'info',
  - FIELD: format: winston.format.json(),
  - DO: transports
  - DO: })
  - DO: logger.setLogger(customLogger)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET performanceService TO roditClient.getPerformanceService()
  - NOTE: Record incoming request
  - DO: performanceService.recordRequest(req)
  - NOTE: Record custom metrics with labels
  - DO: performanceService.recordMetric('operation_duration', 150, {
  - FIELD: operation: 'db_query',
  - FIELD: table: 'users',
  - FIELD: status: 'success'
  - DO: })
  - NOTE: Record errors
  - DO: performanceService.recordMetric('error_count', 1, {
  - FIELD: method: req.method,
  - FIELD: path: req.path,
  - FIELD: status: res.statusCode
  - DO: })
  - NOTE: Get aggregated metrics
  - SET metrics TO performanceService.getMetrics()
  - FIELD: console.log('Total requests:', metrics.totalRequests)
  - FIELD: console.log('Error count:', metrics.errorCount)
  - FIELD: console.log('Average response time:', metrics.avgResponseTime)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Automatic Request Tracking

Integrate performance tracking into your middleware:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Performance monitoring middleware
  - DO: app.use((req, res, next) => {
  - DO: req.startTime = Date.now()
  - SET performanceService TO roditClient.getPerformanceService()
  - CHECK CONDITION: if (performanceService) {
  - DO: performanceService.recordRequest(req)
  - }
  - DO: res.on('finish', () => {
  - SET duration TO Date.now() - req.startTime
  - CHECK CONDITION: if (performanceService) {
  - NOTE: Record request duration
  - DO: performanceService.recordMetric('request_duration_ms', duration, {
  - FIELD: method: req.method,
  - FIELD: path: req.path,
  - FIELD: status: res.statusCode
  - DO: })
  - NOTE: Record errors
  - CHECK CONDITION: if (res.statusCode >= 400) {
  - DO: performanceService.recordMetric('error_count', 1, {
  - FIELD: method: req.method,
  - FIELD: path: req.path,
  - FIELD: status: res.statusCode
  - DO: })
  - }
  - }
  - DO: })
  - DO: next()
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Session Performance Metrics

Track session-related performance:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET sessionManager TO roditClient.getSessionManager()
  - NOTE: Get validation cache statistics
  - SET cacheStats TO sessionManager.getValidationCacheStats()
  - DO: logger.info('Session cache performance', {
  - FIELD: component: 'SessionManager',
  - FIELD: totalEntries: cacheStats.totalEntries,
  - FIELD: validEntries: cacheStats.validEntries,
  - FIELD: expiredEntries: cacheStats.expiredEntries,
  - FIELD: cacheTTL: cacheStats.cacheTTL,
  - FIELD: cacheEnabled: cacheStats.cacheEnabled
  - DO: })
  - NOTE: Get storage information
  - SET storageInfo TO await sessionManager.getStorageInfo()
  - DO: logger.info('Session storage status', {
  - FIELD: component: 'SessionManager',
  - FIELD: storageType: storageInfo.type,
  - FIELD: sessionCount: storageInfo.sessionCount,
  - FIELD: timestamp: storageInfo.timestamp
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Custom Metrics

Record application-specific metrics:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET performanceService TO roditClient.getPerformanceService()
  - NOTE: Database operation timing
  - SET dbStart TO Date.now()
  - SET result TO await db.query('SELECT * FROM users')
  - SET dbDuration TO Date.now() - dbStart
  - DO: performanceService.recordMetric('db_query_duration', dbDuration, {
  - FIELD: operation: 'select',
  - FIELD: table: 'users',
  - FIELD: rowCount: result.length
  - DO: })
  - NOTE: External API call timing
  - SET apiStart TO Date.now()
  - SET apiResponse TO await fetch('https://api.example.com/data')
  - SET apiDuration TO Date.now() - apiStart
  - DO: performanceService.recordMetric('external_api_duration', apiDuration, {
  - FIELD: endpoint: 'api.example.com',
  - FIELD: status: apiResponse.status,
  - FIELD: success: apiResponse.ok
  - DO: })
  - NOTE: Business metrics
  - DO: performanceService.recordMetric('user_action', 1, {
  - FIELD: action: 'comment_created',
  - FIELD: userId: req.user.id,
  - FIELD: timestamp: new Date().toISOString()
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

 ## Webhooks
 
 ### Overview

The SDK supports sending webhooks to multiple endpoints for important events. Webhook URLs are configured in the RODiT token metadata.

**Key Features:**
- **Custom Endpoints** - Send webhooks to any endpoint path (e.g., `/hooks/wake`, `/hooks/agent`, `/webhook`)
- **Non-blocking** - Webhooks sent asynchronously without blocking the main response
- **Error Resilient** - Webhook failures don't affect the main operation

Webhooks are configured in your RODiT token:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: "webhook_url": "https://webhook.example.com:7443",
  - FIELD: "webhook_cidr": "0.0.0.0/0"
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Sending Webhooks to Default Endpoint

Send webhooks to the default `/webhook` endpoint:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Get webhook handler from client
  - SET roditClient TO req.app.locals.roditClient
  - NOTE: Send webhook for an event
  - SET webhookPayload TO {
  - FIELD: event: 'comment_created',
  - FIELD: data: {
  - FIELD: id: comment.id,
  - FIELD: author: comment.author,
  - FIELD: timestamp: new Date().toISOString()
  - DO: },
  - FIELD: isError: false
  - DO: }
  - DO: try {
  - SET result TO await roditClient.sendWebhook(webhookPayload, req)
  - CHECK CONDITION: if (result.success) {
  - DO: logger.info('Webhook sent successfully', {
  - FIELD: component: 'CRUDA',
  - FIELD: event: webhookPayload.event,
  - FIELD: requestId: req.requestId
  - DO: })
  - }
  - DO: } catch (error) {
  - NOTE: Webhook failures don't crash the application
  - DO: logger.warn('Webhook delivery failed', {
  - FIELD: component: 'CRUDA',
  - FIELD: event: webhookPayload.event,
  - FIELD: error: error.message,
  - FIELD: requestId: req.requestId
  - DO: })
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Sending Webhooks to Custom Endpoints

Send webhooks to specific endpoints like `/hooks/wake` or `/hooks/agent`:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET roditClient TO req.app.locals.roditClient
  - SET webhookPayload TO {
  - FIELD: event: 'heartbeat_request',
  - FIELD: data: {
  - FIELD: timestamp: new Date().toISOString(),
  - FIELD: source: '/api/testhola'
  - }
  - DO: }
  - NOTE: Send to /hooks/wake endpoint (trigger immediate heartbeat)
  - WAIT FOR: roditClient.sendWebhookToEndpoint(webhookPayload, '/hooks/wake', req)
  - NOTE: Send to /hooks/agent endpoint (run isolated agent task)
  - WAIT FOR: roditClient.sendWebhookToEndpoint(webhookPayload, '/hooks/agent', req)
  - NOTE: Send to custom endpoint
  - WAIT FOR: roditClient.sendWebhookToEndpoint(webhookPayload, '/hooks/custom', req)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Convenience Methods for Common Endpoints

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET roditClient TO req.app.locals.roditClient
  - SET payload TO {
  - FIELD: event: 'test_event',
  - FIELD: data: { timestamp: new Date().toISOString() }
  - DO: }
  - NOTE: Send to /hooks/wake (heartbeat confirmation)
  - WAIT FOR: roditClient.sendWakeHook(payload, req)
  - NOTE: Send to /hooks/agent (agent task confirmation)
  - WAIT FOR: roditClient.sendAgentHook(payload, req)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Webhook Endpoint Purposes

| Endpoint | Purpose | Use Case |
|----------|---------|----------|
| `/webhook` | Default webhook endpoint | General event notifications |
| `/hooks/wake` | Trigger immediate heartbeat | Enqueue system event for main session |
| `/hooks/agent` | Run isolated agent task | Execute background tasks with optional reply to messaging channels |

### Webhook Error Handling

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Graceful webhook handling in CRUDA operations
  - SET logAndSendWebhook TO async (payload, req = null) => {
  - DO: try {
  - SET roditClient TO req?.app?.locals?.roditClient
  - CHECK CONDITION: if (!roditClient) {
  - DO: logger.warn('RoditClient not available, skipping webhook', {
  - FIELD: component: 'CRUDA',
  - FIELD: event: payload?.event
  - DO: })
  - RETURN { success: false, error: 'RoditClient not available' }
  - }
  - RETURN await roditClient.sendWebhook(payload, req)
  - DO: } catch (error) {
  - NOTE: Log but don't throw - webhook failures shouldn't crash the app
  - DO: logger.error('Webhook delivery failed', {
  - FIELD: component: 'CRUDA',
  - FIELD: event: payload?.event,
  - FIELD: error: error.message
  - DO: })
  - RETURN { success: false, error: error.message }
  - }
  - DO: }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Development/Testing Webhooks

The `/api/testhola` endpoint sends test webhooks in development mode (`NODE_ENV === 'development'`):

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Event: testhola_validation_success
  - NOTE: Sent to: /hooks/wake and /hooks/agent (development only)
  - {
  - FIELD: "event": "testhola_validation_success",
  - FIELD: "data": {
  - FIELD: "peerTokenId": "bcdfhjkmnpqr",
  - FIELD: "serverTokenId": "bcdfhjkmnpqr",
  - FIELD: "recipient": "MUNDO",
  - FIELD: "timestamp": "2026-04-24T14:30:00.000Z",
  - FIELD: "endpoint": "/api/testhola"
  - }
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Use Case:** Test webhook delivery and signature validation during development without needing a main deployment.

## Advanced Usage

### Route Module Pattern

Create reusable route modules that access the shared RoditClient:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: routes/protected.js
  - SET express TO require('express')
  - DO: const { logger } = require('@rodit/rodit-auth-be')
  - SET router TO express.Router()
  - NOTE: Middleware that uses the shared client
  - SET authenticate TO (req, res, next) => {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authentication service unavailable' })
  - }
  - RETURN client.authenticate(req, res, next)
  - DO: }
  - SET authorize TO (req, res, next) => {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authentication service unavailable' })
  - }
  - RETURN client.authorize(req, res, next)
  - DO: }
  - NOTE: Protected route with full authentication and authorization
  - DO: router.get('/data', authenticate, authorize, async (req, res) => {
  - SET startTime TO Date.now()
  - DO: try {
  - NOTE: Your business logic here
  - SET data TO await processUserData(req.user.id)
  - DO: logger.infoWithContext('Data retrieved successfully', {
  - FIELD: component: 'ProtectedRoutes',
  - FIELD: method: 'getData',
  - FIELD: userId: req.user.id,
  - FIELD: requestId: req.requestId,
  - FIELD: duration: Date.now() - startTime
  - DO: })
  - FIELD: res.json({ data, requestId: req.requestId })
  - DO: } catch (error) {
  - DO: logger.errorWithContext('Failed to retrieve data', {
  - FIELD: component: 'ProtectedRoutes',
  - FIELD: method: 'getData',
  - FIELD: userId: req.user.id,
  - FIELD: requestId: req.requestId,
  - FIELD: duration: Date.now() - startTime,
  - FIELD: error: error.message
  - DO: }, error)
  - DO: res.status(500).json({
  - FIELD: error: 'Internal server error',
  - FIELD: requestId: req.requestId
  - DO: })
  - }
  - DO: })
  - DO: module.exports = router
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Portal Authentication (Server-to-Server)

For server-to-server authentication (e.g., minting client tokens):

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: routes/signclient.js
  - SET router TO express.Router()
  - DO: router.post('/signclient', authenticate, authorize, async (req, res) => {
  - DO: const { tobesignedValues, mintingfee, mintingfeeaccount } = req.body
  - SET client TO req.app.locals.roditClient
  - SET logger TO client.getLogger()
  - DO: try {
  - NOTE: Validate requested permissions against server's permissions
  - SET configObject TO await client.getConfigOwnRodit()
  - SET serverPermissions TO JSON.parse(
  - DO: configObject.own_rodit.metadata.permissioned_routes || '{}'
  - DO: )
  - SET requestedPermissions TO JSON.parse(
  - DO: tobesignedValues.permissioned_routes || '{}'
  - DO: )
  - NOTE: Validate that all requested routes exist in server config
  - NOTE: (Implementation details in actual code)
  - NOTE: Authenticate to portal and mint client token
  - SET port TO configObject.port || 8443
  - SET result TO await client.login_portal(configObject, port)
  - CHECK CONDITION: if (result.error) {
  - RETURN res.status(500).json({
  - FIELD: error: 'Portal authentication failed',
  - FIELD: details: result.message,
  - FIELD: requestId: req.requestId
  - DO: })
  - }
  - NOTE: Sign the client token via portal
  - SET signedToken TO await signPortalRodit(
  - DO: port,
  - DO: tobesignedValues,
  - DO: mintingfee,
  - DO: mintingfeeaccount,
  - DO: client
  - DO: )
  - DO: res.json({
  - DO: signedToken,
  - FIELD: requestId: req.requestId
  - DO: })
  - DO: } catch (error) {
  - DO: logger.errorWithContext('Client token minting failed', {
  - FIELD: component: 'SignClient',
  - FIELD: requestId: req.requestId,
  - FIELD: error: error.message
  - DO: }, error)
  - DO: res.status(500).json({
  - FIELD: error: 'Token minting failed',
  - FIELD: requestId: req.requestId
  - DO: })
  - }
  - DO: })
  - DO: module.exports = router
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: "serviceprovider_id": "bc=near.org;sc=roditcorp-com.near;id=01K8QECHMKFVNWQ54PJ2W2GMA7;id=01K8QECHMM1214VMDHSH7JM6H8"
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### URL Construction Method

The SDK uses `roditClient.getPortalUrl(serviceProviderId, port)` to construct the SignPortal URL:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET client TO req.app.locals.roditClient
  - SET configObject TO await client.getConfigOwnRodit()
  - SET serviceProviderId TO configObject.own_rodit.metadata.serviceprovider_id
  - SET portalPort TO 8443
  - NOTE: Automatically constructs: https://signportal.<domain>.<tld>:8443
  - SET portalUrl TO client.getPortalUrl(serviceProviderId, portalPort)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET client TO req.app.locals.roditClient
  - SET logger TO client.getLogger()
  - DO: try {
  - SET configObject TO await client.getConfigOwnRodit()
  - SET serviceProviderId TO configObject.own_rodit.metadata.serviceprovider_id
  - DO: logger.info('RODiT Configuration', {
  - FIELD: component: 'SignPortal',
  - DO: serviceProviderId,
  - FIELD: hasServiceProviderId: !!serviceProviderId
  - DO: })
  - CHECK CONDITION: if (serviceProviderId) {
  - SET portalUrl TO client.getPortalUrl(serviceProviderId, 8443)
  - DO: logger.info('SignPortal URL constructed', {
  - FIELD: component: 'SignPortal',
  - DO: portalUrl
  - DO: })
  - }
  - DO: } catch (error) {
  - DO: logger.error('SignPortal URL construction failed', {
  - FIELD: component: 'SignPortal',
  - FIELD: error: error.message
  - DO: })
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### CRUDA Operations Example

Complete CRUD implementation with authentication, authorization, webhooks, and performance tracking:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: protected/cruda.js
  - SET express TO require('express')
  - SET router TO express.Router()
  - DO: const { RoditClient } = require('@rodit/rodit-auth-be')
  - SET sqlite3 TO require('sqlite3')
  - DO: const { open } = require('sqlite')
  - DO: const { ulid } = require('ulid')
  - SET sdkClient TO new RoditClient()
  - SET logger TO sdkClient.getLogger()
  - DO: let db
  - NOTE: Initialize database
  - SET initializeDatabase TO async () => {
  - SET db TO await open({
  - FIELD: filename: '/app/data/database.sqlite',
  - FIELD: driver: sqlite3.Database
  - DO: })
  - WAIT FOR: db.run(`CREATE TABLE IF NOT EXISTS comments (
  - DO: id INTEGER PRIMARY KEY AUTOINCREMENT,
  - DO: comment TEXT NOT NULL,
  - DO: author TEXT,
  - DO: created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  - DO: updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  - DO: )`)
  - DO: }
  - NOTE: Webhook helper
  - SET logAndSendWebhook TO async (payload, req) => {
  - DO: try {
  - SET roditClient TO req?.app?.locals?.roditClient
  - CHECK CONDITION: if (!roditClient) return { success: false }
  - RETURN await roditClient.send_webhook(payload, req)
  - DO: } catch (error) {
  - FIELD: logger.error('Webhook failed', { error: error.message })
  - RETURN { success: false, error: error.message }
  - }
  - DO: }
  - NOTE: CREATE
  - DO: router.post('/create', async (req, res) => {
  - DO: const { comment, author } = req.body
  - SET requestId TO req.requestId || ulid()
  - DO: try {
  - SET result TO await db.run(
  - DO: 'INSERT INTO comments (comment, author) VALUES (?, ?)',
  - DO: [comment, author || req.user.roditId]
  - DO: )
  - NOTE: Send webhook
  - WAIT FOR: logAndSendWebhook({
  - FIELD: event: 'comment_created',
  - FIELD: data: { id: result.lastID, comment, author },
  - FIELD: isError: false
  - DO: }, req)
  - FIELD: res.json({ id: result.lastID, requestId })
  - DO: } catch (error) {
  - DO: logger.errorWithContext('Create failed', {
  - FIELD: component: 'CRUDA',
  - FIELD: error: error.message,
  - DO: requestId
  - DO: }, error)
  - FIELD: res.status(500).json({ error: 'Create failed', requestId })
  - }
  - DO: })
  - NOTE: LIST
  - DO: router.post('/list', async (req, res) => {
  - DO: try {
  - SET records TO await db.all(
  - DO: 'SELECT * FROM comments ORDER BY created_at DESC'
  - DO: )
  - FIELD: res.json({ records, requestId: req.requestId })
  - DO: } catch (error) {
  - FIELD: res.status(500).json({ error: 'List failed', requestId: req.requestId })
  - }
  - DO: })
  - NOTE: READ
  - DO: router.post('/read', async (req, res) => {
  - DO: const { id } = req.body
  - DO: try {
  - SET record TO await db.get('SELECT * FROM comments WHERE id = ?', [id])
  - CHECK CONDITION: if (!record) {
  - RETURN res.status(404).json({ error: 'Not found', requestId: req.requestId })
  - }
  - FIELD: res.json({ record, requestId: req.requestId })
  - DO: } catch (error) {
  - FIELD: res.status(500).json({ error: 'Read failed', requestId: req.requestId })
  - }
  - DO: })
  - NOTE: UPDATE
  - DO: router.post('/update', async (req, res) => {
  - DO: const { id, comment } = req.body
  - DO: try {
  - WAIT FOR: db.run(
  - DO: 'UPDATE comments SET comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
  - DO: [comment, id]
  - DO: )
  - WAIT FOR: logAndSendWebhook({
  - FIELD: event: 'comment_updated',
  - FIELD: data: { id, comment },
  - FIELD: isError: false
  - DO: }, req)
  - FIELD: res.json({ success: true, requestId: req.requestId })
  - DO: } catch (error) {
  - FIELD: res.status(500).json({ error: 'Update failed', requestId: req.requestId })
  - }
  - DO: })
  - NOTE: DELETE
  - DO: router.post('/destroy', async (req, res) => {
  - DO: const { id } = req.body
  - DO: try {
  - WAIT FOR: db.run('DELETE FROM comments WHERE id = ?', [id])
  - WAIT FOR: logAndSendWebhook({
  - FIELD: event: 'comment_deleted',
  - FIELD: data: { id },
  - FIELD: isError: false
  - DO: }, req)
  - FIELD: res.json({ success: true, requestId: req.requestId })
  - DO: } catch (error) {
  - FIELD: res.status(500).json({ error: 'Delete failed', requestId: req.requestId })
  - }
  - DO: })
  - NOTE: Export initialization function
  - DO: module.exports = router
  - DO: module.exports.initializeDatabase = initializeDatabase
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

## API Reference

### RoditClient Class

The main client class for all RODiT operations.

#### Static Methods

##### RoditClient.create(role)

Create and initialize a RODiT client in one step.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET client TO await RoditClient.create('server');  // For server applications
  - SET client TO await RoditClient.create('client');  // For client applications
  - SET client TO await RoditClient.create('portal');  // For portal authentication
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Parameters:**
- `role` (string): Client role - `'server'`, `'client'`, or `'portal'`

**Returns:** `Promise<RoditClient>` - Fully initialized client instance

**Throws:** Error if initialization fails (e.g., missing credentials, Vault connection failure)

#### Instance Methods

##### authenticate(req, res, next)

Express middleware for authenticating API requests. Validates JWT tokens and populates `req.user`.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET authenticate TO (req, res, next) => roditClient.authenticate(req, res, next)
  - DO: app.use('/api/protected', authenticate, handler)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET authenticateLogout TO (req, res, next) => roditClient.authenticateForLogout(req, res, next)
  - DO: app.post('/api/logout', authenticateLogout, (req, res) => roditClient.logout_client(req, res))
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Use case:** clean logout when token is expired but cryptographically valid.

##### authorize(req, res, next)

Express middleware for validating route permissions. Must be used after `authenticate`.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET authorize TO (req, res, next) => roditClient.authorize(req, res, next)
  - DO: app.use('/api/admin', authenticate, authorize, handler)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Validates:** User has permission for the requested route and HTTP method

##### login_client(req, res)

Handle Express login requests from clients. Validates RODiT credentials and issues JWT token.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: app.post('/api/login', (req, res) => roditClient.login_client(req, res))
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Request Body:** `login_client` accepts `accountid`, `timestamp`, and `base64url_signature`.

**Response:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: jwt_token: '<jwt-token>',
  - FIELD: requestId: '01HQXYZ...'
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

##### logout_client(req, res)

Handle Express logout requests. Closes session and invalidates JWT token.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET authenticateLogout TO (req, res, next) => roditClient.authenticateForLogout(req, res, next)
  - DO: app.post('/api/logout', authenticateLogout, (req, res) => {
  - RETURN roditClient.logout_client(req, res)
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Response:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: message: 'Logout successful',
  - FIELD: terminationToken: '<jwt-token>',  // Short-lived token
  - FIELD: requestId: '01HQXYZ...'
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

##### login_portal(configObject, port)

Authenticate to RODiT portal for server-to-server operations using account-based login payloads.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET configObject TO await roditClient.getConfigOwnRodit()
  - SET result TO await roditClient.login_portal(configObject, 8443)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `Promise<Object>` - Portal authentication result

##### login_server(options)

Authenticate to a peer API using account-based login semantics: sign **`accountid + timestamp_iso`** and POST **`{ accountid, timestamp, base64url_signature }`**.

Optional: `options.timestamp`, `options.loginPath`.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET result TO await roditClient.login_server({
  - FIELD: loginPath: '/api/login'  // optional; default shown
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `Promise<Object>` - Authentication result with `jwt_token`

##### logout_server()

Logout from server-to-server session.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET result TO await roditClient.logout_server()
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `Promise<Object>` - Logout result with session closure status

##### getConfigOwnRodit()

Get the complete RODiT configuration including token metadata.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET configObject TO await roditClient.getConfigOwnRodit()
  - SET metadata TO configObject.own_rodit.metadata
  - SET tokenId TO configObject.own_rodit.token_id
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `Promise<Object>` - Complete RODiT configuration

**Structure:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - {
  - FIELD: own_rodit: {
  - FIELD: token_id: string,
  - FIELD: metadata: {
  - FIELD: jwt_duration: number,
  - FIELD: max_requests: string,
  - FIELD: maxrq_window: string,
  - FIELD: permissioned_routes: string,  // JSON string
  - FIELD: subjectuniqueidentifier_url: string,
  - FIELD: webhook_url: string,
  - NOTE: ... other metadata fields
  - }
  - DO: },
  - FIELD: port: number
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

##### isOperationPermitted(method, path)

Check if an operation is permitted based on token permissions.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET hasPermission TO roditClient.isOperationPermitted('POST', '/api/admin/users')
  - CHECK CONDITION: if (!hasPermission) {
  - RETURN res.status(403).json({ error: 'Forbidden' })
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Parameters:**
- `method` (string): HTTP method
- `path` (string): API path

**Returns:** `boolean`

##### getStateManager()

Get the authentication state manager.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET stateManager TO roditClient.getStateManager()
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `AuthStateManager` instance

##### getRoditManager()

Get the RODiT manager for credential operations.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET roditManager TO roditClient.getRoditManager()
  - SET credentials TO await roditManager.getCredentials('server')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `RoditManager` instance

##### getSessionManager()

Get the session manager.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET sessionManager TO roditClient.getSessionManager()
  - SET activeCount TO await sessionManager.getActiveSessionCount()
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `SessionManager` instance

##### getLogger()

Get the logger instance.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET logger TO roditClient.getLogger()
  - FIELD: logger.info('Message', { component: 'MyComponent' })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `Logger` instance

##### getLoggingMiddleware()

Get the logging middleware.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET loggingmw TO roditClient.getLoggingMiddleware()
  - DO: app.use(loggingmw)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** Express middleware function

##### getRateLimitMiddleware()

Get the rate limiting middleware factory.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET ratelimitmw TO roditClient.getRateLimitMiddleware()
  - SET limiter TO ratelimitmw(100, 900);  // 100 requests per 15 minutes
  - DO: app.use(limiter)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Parameters:**
- `maxRequests` (number): Maximum requests allowed
- `windowSeconds` (number): Time window in seconds

**Returns:** Express middleware function

##### getPerformanceService()

Get the performance tracking service.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET performanceService TO roditClient.getPerformanceService()
  - DO: performanceService.recordRequest(req)
  - FIELD: performanceService.recordMetric('operation_duration', 150, { operation: 'db_query' })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `PerformanceService` instance

##### getConfig()

Get the configuration service.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET config TO roditClient.getConfig()
  - SET dbPath TO config.get('API_DEFAULT_OPTIONS.DB_PATH')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `Config` instance

##### getWebhookHandler()

Get the webhook handler.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET webhookHandler TO roditClient.getWebhookHandler()
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Returns:** `WebhookHandler` instance

##### send_webhook(payload, req)

Send a webhook notification.

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET result TO await roditClient.send_webhook({
  - FIELD: event: 'user_action',
  - FIELD: data: { userId: '123', action: 'login' },
  - FIELD: isError: false
  - DO: }, req)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: const {
  - DO: RoditClient,           // Main client class
  - DO: logger,                // Logger instance
  - DO: stateManager,          // Authentication state manager
  - DO: roditManager,          // RODiT credential manager
  - DO: sessionManager,        // Session manager instance
  - DO: blockchainService,     // Blockchain operations
  - DO: utils,                 // Utility functions
  - DO: config,                // Configuration service
  - DO: performanceService,    // Performance tracking
  - DO: authenticate_apicall,  // Authentication middleware
  - DO: authenticate_logout,   // Logout authentication middleware (expired-token tolerant)
  - DO: login_client,          // Login handler
  - DO: logout_client,         // Logout handler
  - DO: login_client_withnep413, // NEP-413 login
  - DO: login_portal,          // Portal authentication
  - DO: login_server,          // Outbound peer login
  - DO: logout_server,         // Server logout
  - DO: validate_jwt_token_be, // JWT validation
  - DO: generate_jwt_token,    // JWT generation
  - DO: validatepermissions,   // Permission middleware
  - DO: webhookHandler,        // Webhook handler
  - DO: versioningMiddleware,  // API versioning
  - DO: loggingmw,             // Logging middleware
  - DO: ratelimitmw,           // Rate limiting middleware
  - DO: versionManager,        // Version manager
  - DO: VersionManager,        // Version manager class
  - DO: nearorg_rpc_timestamp  // Blockchain RPC timestamp function
  - DO: } = require('@rodit/rodit-auth-be')
  - NOTE: Note: Session storage configuration functions are available via:
  - NOTE: const { setExpressSessionStore, configureStorageFromConfig,
  - NOTE: createExpressSessionMiddleware, InMemorySessionStorage }
  - NOTE: = require('@rodit/rodit-auth-be/lib/auth/sessionmanager');
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### RODiT Token Metadata Fields

When you call `roditClient.getConfigOwnRodit()`, you get access to these metadata fields:

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string | Unique RODiT token identifier |
| `allowed_cidr` | string | Permitted IP address ranges (CIDR format) |
| `allowed_iso3166list` | string | Geographic restrictions (JSON string) |
| `jwt_duration` | number | JWT token lifetime in seconds |
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

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Single initialization
  - DO: async function startServer() {
  - SET roditClient TO await RoditClient.create('server')
  - DO: app.locals.roditClient = roditClient
  - NOTE: Mount protected routes AFTER client initialization
  - SET authenticate TO (req, res, next) => roditClient.authenticate(req, res, next)
  - SET authorize TO (req, res, next) => roditClient.authorize(req, res, next)
  - DO: app.use('/api/echo', authenticate, echoRoutes)
  - DO: app.use('/api/cruda', authenticate, authorize, crudaRoutes)
  - NOTE: ... rest of server setup
  - }
  - NOTE: ❌ Bad - Multiple initializations
  - DO: app.get('/route1', async (req, res) => {
  - SET client TO await RoditClient.create('server'); // Don't do this
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 2. Use App.locals for Shared Access

Store the client in `app.locals` for access across all routes:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Shared instance via app.locals
  - SET router TO express.Router()
  - DO: router.get('/data', (req, res) => {
  - SET client TO req.app.locals.roditClient
  - SET logger TO client.getLogger()
  - DO: logger.info('Processing request', {
  - FIELD: component: 'DataRoute',
  - FIELD: userId: req.user?.id,
  - FIELD: requestId: req.requestId
  - DO: })
  - FIELD: res.json({ data: 'example' })
  - DO: })
  - NOTE: ❌ Bad - Creating new instances in routes
  - DO: const { RoditClient } = require('@rodit/rodit-auth-be')
  - SET client TO new RoditClient(); // Don't do this in routes
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 3. Proper Error Handling

Always wrap SDK operations in try-catch blocks and include request context:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Comprehensive error handling
  - DO: app.get('/api/data', authenticate, async (req, res) => {
  - SET startTime TO Date.now()
  - SET client TO req.app.locals.roditClient
  - SET logger TO client.getLogger()
  - DO: try {
  - SET data TO await processData(req.user.id)
  - DO: logger.infoWithContext('Request successful', {
  - FIELD: component: 'API',
  - FIELD: method: 'getData',
  - FIELD: userId: req.user.id,
  - FIELD: requestId: req.requestId,
  - FIELD: duration: Date.now() - startTime
  - DO: })
  - FIELD: res.json({ data, requestId: req.requestId })
  - DO: } catch (error) {
  - DO: logger.errorWithContext('Request failed', {
  - FIELD: component: 'API',
  - FIELD: method: 'getData',
  - FIELD: userId: req.user.id,
  - FIELD: requestId: req.requestId,
  - FIELD: duration: Date.now() - startTime,
  - FIELD: error: error.message
  - DO: }, error)
  - DO: res.status(500).json({
  - FIELD: error: 'Internal server error',
  - FIELD: requestId: req.requestId
  - DO: })
  - }
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 4. Structured Logging

Use consistent logging patterns with context:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Structured logging with context
  - SET logger TO req.app.locals.roditClient.getLogger()
  - DO: logger.infoWithContext('User action completed', {
  - FIELD: component: 'UserService',
  - FIELD: action: 'updateProfile',
  - FIELD: userId: user.id,
  - FIELD: requestId: req.requestId,
  - FIELD: duration: Date.now() - startTime,
  - FIELD: changes: Object.keys(updates)
  - DO: })
  - NOTE: For errors, pass the error object
  - DO: logger.errorWithContext('Operation failed', {
  - FIELD: component: 'UserService',
  - FIELD: action: 'updateProfile',
  - FIELD: userId: user.id,
  - FIELD: requestId: req.requestId,
  - FIELD: error: error.message
  - DO: }, error)
  - NOTE: ❌ Bad - Unstructured logging
  - DO: console.log('User updated profile'); // Don't do this
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 5. Environment-Specific Configuration

Use environment variables for sensitive and environment-specific values:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Environment-aware configuration
  - SET config TO roditClient.getConfig()
  - SET logLevel TO config.get('LOG_LEVEL', 'info')
  - SET isMainDeploy TO ['info', 'warn', 'error'].includes(logLevel)
  - NOTE: Main should use vault credentials
  - CHECK CONDITION: if (isMainDeploy && process.env.RODIT_NEAR_CREDENTIALS_SOURCE !== 'vault') {
  - DO: logger.warn('Main environment should use vault credentials', {
  - FIELD: component: 'Configuration',
  - FIELD: environment: 'main',
  - FIELD: credentialsSource: process.env.RODIT_NEAR_CREDENTIALS_SOURCE || 'not-set'
  - DO: })
  - }
  - NOTE: Configure session storage before initializing client
  - CHECK CONDITION: if (isMainDeploy) {
  - SET SQLiteStore TO require('connect-sqlite3')(require('express-session'))
  - SET sessionStore TO new SQLiteStore({
  - FIELD: db: 'sessions.db',
  - FIELD: dir: config.get('API_DEFAULT_OPTIONS.DB_PATH', './data')
  - DO: })
  - DO: setExpressSessionStore(sessionStore)
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 6. Graceful Shutdown

Implement proper shutdown handling:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Graceful shutdown
  - SET shutdown TO async (signal) => {
  - SET logger TO roditClient.getLogger()
  - DO: logger.info('Shutting down gracefully', {
  - FIELD: component: 'AppLifecycle',
  - FIELD: signal: signal || 'unknown',
  - FIELD: time: new Date().toISOString()
  - DO: })
  - CHECK CONDITION: if (server) {
  - DO: server.close(async () => {
  - DO: logger.info('HTTP server closed')
  - NOTE: Close database connections
  - CHECK CONDITION: if (db && typeof db.close === 'function') {
  - WAIT FOR: db.close()
  - DO: logger.info('Database connections closed')
  - }
  - NOTE: Close session store
  - CHECK CONDITION: if (sessionStore && typeof sessionStore.close === 'function') {
  - WAIT FOR: new Promise((resolve) => sessionStore.close(resolve))
  - DO: logger.info('Session store closed')
  - }
  - DO: process.exit(0)
  - DO: })
  - NOTE: Force shutdown after timeout
  - DO: setTimeout(() => {
  - DO: logger.error('Forced shutdown after timeout')
  - DO: process.exit(1)
  - DO: }, 10000)
  - }
  - DO: }
  - DO: process.on('SIGTERM', () => shutdown('SIGTERM'))
  - DO: process.on('SIGINT', () => shutdown('SIGINT'))
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 7. Request Context and Performance Tracking

Always include request context and track performance:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Request context and performance tracking
  - DO: app.use((req, res, next) => {
  - DO: req.requestId = req.headers['x-request-id'] || ulid()
  - DO: req.startTime = Date.now()
  - DO: next()
  - DO: })
  - NOTE: Performance monitoring
  - DO: app.use((req, res, next) => {
  - SET performanceService TO roditClient.getPerformanceService()
  - CHECK CONDITION: if (performanceService) {
  - DO: performanceService.recordRequest(req)
  - }
  - DO: res.on('finish', () => {
  - SET duration TO Date.now() - req.startTime
  - CHECK CONDITION: if (performanceService) {
  - DO: performanceService.recordMetric('request_duration_ms', duration, {
  - FIELD: method: req.method,
  - FIELD: path: req.path,
  - FIELD: status: res.statusCode
  - DO: })
  - CHECK CONDITION: if (res.statusCode >= 400) {
  - DO: performanceService.recordMetric('error_count', 1, {
  - FIELD: method: req.method,
  - FIELD: path: req.path,
  - FIELD: status: res.statusCode
  - DO: })
  - }
  - }
  - DO: })
  - DO: next()
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 8. Login Endpoint Protection

**CRITICAL:** Never protect the login endpoint with authentication middleware:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Login endpoint without authentication
  - DO: app.post('/api/login', (req, res) => {
  - DO: req.logAction = 'login-attempt'
  - RETURN roditClient.login_client(req, res)
  - DO: })
  - NOTE: ❌ Bad - Login endpoint with authentication (creates circular dependency)
  - DO: app.post('/api/login', authenticate, (req, res) => {  // DON'T DO THIS
  - RETURN roditClient.login_client(req, res)
  - DO: })
  - NOTE: ✅ Better - Logout endpoint with logout-specific authentication
  - SET authenticateLogout TO (req, res, next) => roditClient.authenticateForLogout(req, res, next)
  - DO: app.post('/api/logout', authenticateLogout, (req, res) => {
  - DO: req.logAction = 'logout-attempt'
  - RETURN roditClient.logout_client(req, res)
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### 9. Route Mounting Order

Mount protected routes AFTER client initialization:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Good - Correct order
  - DO: async function startServer() {
  - NOTE: 1. Configure session storage
  - DO: setExpressSessionStore(sessionStore)
  - NOTE: 2. Initialize client
  - SET roditClient TO await RoditClient.create('server')
  - DO: app.locals.roditClient = roditClient
  - NOTE: 3. Create middleware
  - SET authenticate TO (req, res, next) => roditClient.authenticate(req, res, next)
  - SET authenticateLogout TO (req, res, next) => roditClient.authenticateForLogout(req, res, next)
  - SET authorize TO (req, res, next) => roditClient.authorize(req, res, next)
  - NOTE: 4. Mount public routes
  - DO: app.post('/api/login', loginRoute)
  - NOTE: 5. Mount protected routes
  - DO: app.use('/api/echo', authenticate, echoRoutes)
  - DO: app.use('/api/cruda', authenticate, authorize, crudaRoutes)
  - DO: app.post('/api/logout', authenticateLogout, logoutRoute)
  - NOTE: 6. Start server
  - DO: app.listen(port)
  - }
  - NOTE: ❌ Bad - Routes mounted before client initialization
  - DO: app.use('/api/echo', authenticate, echoRoutes);  // authenticate is undefined!
  - SET roditClient TO await RoditClient.create('server')
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

## Troubleshooting

### Common Issues

#### 1. Authentication Middleware Errors

**Problem:** `roditClient.authenticate is not a function` or `Cannot read properties of undefined`

**Solution:** Ensure client is initialized and stored in app.locals:
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: ✅ Correct - Check client availability
  - SET authenticate TO (req, res, next) => {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ error: 'Authentication service unavailable' })
  - }
  - RETURN client.authenticate(req, res, next)
  - DO: }
  - NOTE: ❌ Wrong - Direct access without checking
  - SET authenticate TO (req, res, next) => roditClient.authenticate(req, res, next)
  - NOTE: This fails if roditClient is not initialized yet
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### 2. Configuration Not Found

**Problem:** `Failed to initialize RODiT configuration`

**Solutions:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Check environment variables
  - DO: echo $RODIT_NEAR_CREDENTIALS_SOURCE  # Should be 'vault' or 'file'
  - DO: echo $VAULT_ENDPOINT
  - DO: echo $NEAR_CONTRACT_ID
  - DO: echo $SERVICE_NAME
  - NOTE: For vault-based credentials
  - DO: export RODIT_NEAR_CREDENTIALS_SOURCE=vault
  - FIELD: export VAULT_ENDPOINT=https://vault.example.com
  - DO: export VAULT_ROLE_ID=your-role-id
  - DO: export VAULT_SECRET_ID=your-secret-id
  - NOTE: For file-based credentials (development)
  - DO: export RODIT_NEAR_CREDENTIALS_SOURCE=file
  - DO: export CREDENTIALS_FILE_PATH=./credentials/rodit-credentials.json
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

**Verify configuration:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET config TO roditClient.getConfig()
  - FIELD: console.log('NEAR_CONTRACT_ID:', config.get('NEAR_CONTRACT_ID'))
  - FIELD: console.log('SERVICE_NAME:', config.get('SERVICE_NAME'))
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### 3. Missing App.locals Client

**Problem:** `RoditClient not available in app.locals` or `Cannot read properties of undefined (reading 'roditClient')`

**Solution:** Ensure client is stored during initialization:
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: async function startServer() {
  - DO: try {
  - NOTE: Initialize client
  - SET roditClient TO await RoditClient.create('server')
  - NOTE: Store in app.locals BEFORE mounting routes
  - DO: app.locals.roditClient = roditClient
  - NOTE: Verify it's stored
  - CHECK CONDITION: if (!app.locals.roditClient) {
  - DO: throw new Error('Failed to store roditClient in app.locals')
  - }
  - NOTE: Now mount routes
  - SET authenticate TO (req, res, next) => roditClient.authenticate(req, res, next)
  - DO: app.use('/api/protected', authenticate, protectedRoutes)
  - DO: app.listen(port)
  - DO: } catch (error) {
  - FIELD: console.error('Server initialization failed:', error)
  - DO: process.exit(1)
  - }
  - }
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

#### 4. Permission Denied Errors

**Problem:** Routes return 403 Forbidden

**Debug steps:**
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Check token permissions
  - SET configObject TO await roditClient.getConfigOwnRodit()
  - SET permissionedRoutes TO JSON.parse(
  - DO: configObject.own_rodit.metadata.permissioned_routes || '{}'
  - DO: )
  - FIELD: console.log('Configured permissions:', permissionedRoutes)
  - NOTE: Check specific operation
  - SET hasPermission TO roditClient.isOperationPermitted('POST', '/api/cruda/create')
  - FIELD: console.log('Has permission:', hasPermission)
  - NOTE: Verify route path matches exactly
  - FIELD: console.log('Requested path:', req.path);  // Must match permission key exactly
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Verify session storage is configured
  - SET sessionManager TO roditClient.getSessionManager()
  - SET storageInfo TO await sessionManager.getStorageInfo()
  - FIELD: console.log('Storage type:', storageInfo.storageType)
  - FIELD: console.log('Active sessions:', storageInfo.sessionCount)
  - NOTE: Check if token is invalidated
  - SET isInvalidated TO await sessionManager.isTokenInvalidated(jwtToken)
  - FIELD: console.log('Token invalidated:', isInvalidated)
  - NOTE: Enumerate sessions via storage for debugging
  - SET allSessions TO await sessionManager.storage.getAll()
  - FIELD: console.log('Active sessions:', allSessions.filter(s => s.status === 'active').length)
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Check logging configuration
  - DO: export LOG_LEVEL=debug  # Enable debug logging
  - FIELD: export LOKI_URL=https://loki.example.com:3100
  - FIELD: export LOKI_BASIC_AUTH=username:password
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - NOTE: Test logger directly
  - SET logger TO roditClient.getLogger()
  - FIELD: logger.info('Test message', { component: 'Test' })
  - FIELD: logger.error('Test error', { component: 'Test' })
  - NOTE: Check if Loki transport is configured
  - SET transports TO logger.transports
  - FIELD: console.log('Logger transports:', transports.map(t => t.name))
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Debug Mode

Enable debug logging for troubleshooting:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: export LOG_LEVEL=debug  # Use 'debug' or 'trace' for development mode
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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
```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - SET logger TO roditClient.getLogger()
  - NOTE: Enable debug logging programmatically
  - DO: logger.level = 'debug'
  - NOTE: Debug authentication
  - DO: logger.debug('Authenticating request', {
  - FIELD: component: 'Authentication',
  - FIELD: hasAuthHeader: !!req.headers.authorization,
  - FIELD: path: req.path,
  - FIELD: method: req.method
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
```

### Health Checks

Implement comprehensive health check endpoints:

```text
PSEUDOCODE
INPUTS:
  - Use values defined by the surrounding section/context.
STEPS:
  - DO: app.get('/health', async (req, res) => {
  - DO: try {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({
  - FIELD: status: 'error',
  - FIELD: message: 'RoditClient not available'
  - DO: })
  - }
  - SET configObject TO await client.getConfigOwnRodit()
  - SET sessionManager TO client.getSessionManager()
  - SET performanceService TO client.getPerformanceService()
  - SET health TO {
  - FIELD: status: 'healthy',
  - FIELD: timestamp: new Date().toISOString(),
  - FIELD: logLevel: config.get('LOG_LEVEL', 'info'),
  - FIELD: components: {
  - FIELD: roditClient: !!client,
  - FIELD: configuration: !!(configObject && configObject.own_rodit),
  - FIELD: sessionManager: !!sessionManager,
  - FIELD: performanceService: !!performanceService
  - DO: },
  - FIELD: metrics: {
  - FIELD: activeSessions: await sessionManager.getActiveSessionCount(),
  - FIELD: totalRequests: performanceService.getRequestCount(),
  - FIELD: errorCount: performanceService.getErrorCount()
  - DO: },
  - FIELD: roditToken: {
  - FIELD: tokenId: configObject?.own_rodit?.token_id,
  - FIELD: apiUrl: configObject?.own_rodit?.metadata?.subjectuniqueidentifier_url,
  - FIELD: jwtDuration: configObject?.own_rodit?.metadata?.jwt_duration
  - }
  - DO: }
  - DO: res.json(health)
  - DO: } catch (error) {
  - DO: res.status(503).json({
  - FIELD: status: 'error',
  - FIELD: message: error.message,
  - FIELD: timestamp: new Date().toISOString()
  - DO: })
  - }
  - DO: })
  - NOTE: Readiness check (for Kubernetes)
  - DO: app.get('/ready', async (req, res) => {
  - SET client TO req.app.locals.roditClient
  - CHECK CONDITION: if (!client) {
  - RETURN res.status(503).json({ ready: false })
  - }
  - DO: try {
  - SET configObject TO await client.getConfigOwnRodit()
  - SET ready TO !!(configObject && configObject.own_rodit)
  - FIELD: res.status(ready ? 200 : 503).json({ ready })
  - DO: } catch (error) {
  - FIELD: res.status(503).json({ ready: false, error: error.message })
  - }
  - DO: })
  - NOTE: Liveness check (for Kubernetes)
  - DO: app.get('/live', (req, res) => {
  - FIELD: res.json({ alive: true })
  - DO: })
OUTPUTS:
  - Produces the section's intended result using equivalent logic.
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

Copyright (c) 2025 Discernible IO. All rights reserved.
