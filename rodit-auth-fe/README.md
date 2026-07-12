# @rodit/rodit-auth-fe

Part of the [Discernible IO SDK monorepo](../README.md).

A browser-based JavaScript SDK for RODiT (Routable Decentralized Identity Token) authentication and verification. This SDK enables secure authentication flows using NEAR Protocol blockchain, NEP-413 signatures, and JWT tokens for API access control.

> **Note**: This is the **frontend/browser** version of the RODiT authentication SDK. For Node.js/backend environments, use [`@rodit/rodit-auth-be`](https://www.npmjs.com/package/@rodit/rodit-auth-be).

## Overview

This SDK is designed for **browser environments only** and provides:
- **NEP-413 Authentication**: NEAR wallet signature-based authentication
- **RODiT Token Management**: Fetch and verify RODiT tokens from NEAR blockchain
- **JWT Session Management**: Handle JWT tokens with automatic refresh
- **Cryptographic Verification**: Verify RODiT ownership and signatures
- **State Management**: Browser-compatible session and state storage

## Installation

```bash
npm install @rodit/rodit-auth-fe
```

## Frontend vs Backend SDK

| Feature | @rodit/rodit-auth-fe (Frontend) | @rodit/rodit-auth-be (Backend) |
|---------|--------------------------------|-------------------------------|
| **Environment** | Browser only | Node.js only |
| **Use Case** | Client-side web applications | Server-side APIs and services |
| **DNS Verification** | ❌ Skipped (browser limitation) | ✅ Full DNS TXT record verification |
| **Cryptography** | Web Crypto API, tweetnacl | Node.js crypto module |
| **Storage** | sessionStorage, localStorage | File system, databases |
| **NEAR Integration** | NEAR wallet browser integration | Direct RPC calls |
| **JWT Operations** | jwt-decode, tweetnacl verify | Full jose with Node.js features |

**When to use this SDK (`@rodit/rodit-auth-fe`):**
- Building web applications with NEAR wallet integration
- Client-side RODiT authentication flows
- Browser-based API clients
- React, Vue, or other frontend frameworks

**When to use `@rodit/rodit-auth-be`:**
- Building backend API servers
- Server-side RODiT verification with full DNS checks
- Node.js microservices
- API gateways and middleware

## Quick Start

### Basic Setup

```javascript
import { RoditAuthService } from '@rodit/rodit-auth-fe';
import { Wallet } from './near-wallet'; // Your NEAR wallet implementation

// Initialize NEAR wallet
const wallet = new Wallet({
  createAccessKeyFor: 'your-contract.near',
  network: 'mainnet'
});

// Create RODiT authentication service
const roditAuth = new RoditAuthService(
  wallet,
  'https://api.example.com',           // API endpoint
  window.location.origin,              // Callback endpoint
  'your-contract.near',             // Contract ID
  'https://rpcnear.org'       // RPC URL
);
```

### Authentication Flow

```javascript
// 1. Initiate login with NEP-413 signature
await roditAuth.login_server_withnep413({
  callbackUrl: `${window.location.origin}/login`
});

// 2. Handle callback after wallet signature
const loginResult = await roditAuth.handleLoginCallback(window.location.href);
console.log('JWT Token:', loginResult.jwt_token);

// 3. Make authenticated API calls
const response = await roditAuth.fetchWithErrorHandling_fe(
  'https://api.example.com/api/endpoint',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: 'example' })
  }
);
```

## Core Components

### RoditAuthService

Main authentication service class that handles the complete authentication lifecycle.

#### Constructor

```javascript
new RoditAuthService(wallet, apiEndpoint, callbackEndpoint, contractId, rpcUrl)
```

**Parameters:**
- `wallet` - NEAR wallet instance with `accountId` and `viewMethod` support
- `apiEndpoint` - Base URL of the API server (e.g., `https://api.example.com`)
- `callbackEndpoint` - Callback URL for authentication redirects (typically `window.location.origin`)
- `contractId` - NEAR smart contract ID where RODiT tokens are stored
- `rpcUrl` - NEAR RPC endpoint URL (e.g., `https://rpcnear.org`)

#### Key Methods

##### `login_server_withnep413(options)`

Initiates NEP-413 authentication flow with NEAR wallet.

```javascript
await roditAuth.login_server_withnep413({
  callbackUrl: `${window.location.origin}/login`
});
```

**Process:**
1. Fetches user's RODiT token from blockchain
2. Generates cryptographically secure nonce
3. Stores login data in sessionStorage
4. Triggers NEAR wallet signature request

##### `handleLoginCallback(url)`

Processes the callback after wallet signature.

```javascript
const result = await roditAuth.handleLoginCallback(window.location.href);
// Returns: { jwt_token: string, decoded: object }
```

**Process:**
1. Extracts signature from callback URL
2. Validates signature against stored login data
3. Sends authentication request to API server
4. Receives and stores JWT token
5. Sets up automatic token refresh

##### `fetchWithErrorHandling_fe(url, options)`

Makes authenticated API requests with automatic JWT token inclusion.

```javascript
const response = await roditAuth.fetchWithErrorHandling_fe(
  'https://api.example.com/api/endpoint',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: 'value' })
  }
);
```

**Features:**
- Automatically adds JWT token to Authorization header
- Handles token refresh if expired
- Comprehensive error logging
- Returns parsed JSON response

##### `nearorg_wallet_tokensfromaccountid(wallet, contractId, accountId)`

Fetches RODiT tokens owned by a specific NEAR account.

```javascript
const token = await roditAuth.nearorg_wallet_tokensfromaccountid(
  wallet,
  'contract.near',
  'user.near'
);
```

## Exported Functions

### Authentication & Verification

```javascript
import {
  RoditAuthService,
  verify_rodit_ownership,
  verify_rodit_islive,
  verify_rodit_isamatch,
  verify_rodit_isactive_fe,
  verify_rodit_istrusted_issuingsmartcontract_fe,
  verify_peerrodit_getrodit_fe,
  stateManager,
  validateMetadata,
  verifyRoditBeforeMinting,
  verifyRoditPairBeforeMinting
} from '@rodit/rodit-auth-fe';
```

#### `verify_rodit_ownership(peerroditid, peer_rodit, authService)`

Verifies cryptographic ownership of a RODiT token by validating the Ed25519 signature.

#### `verify_rodit_islive(notAfter, notBefore)`

Checks if a RODiT token is within its valid time period.

#### `verify_rodit_isamatch(serviceprovider_id, peer_rodit_id)`

Verifies that a peer RODiT ID matches the service provider ID.

#### `verify_rodit_isactive_fe(tokenId, url)`

Browser-compatible check for RODiT activity status (DNS checks skipped).

#### `verify_peerrodit_getrodit_fe(roditId, timestamp, signature, authService)`

Fetches and verifies a peer RODiT token from the blockchain.

### Blockchain Models

```javascript
import { CONSTANTS, RODiT } from '@rodit/rodit-auth-fe';
```

#### `RODiT` Class

Data model representing a RODiT token with metadata:

```javascript
const rodit = new RODiT();
rodit.token_id = "bc=near.org;sc=contract.near;id=01ABC123...";
rodit.owner_id = "user.near";
rodit.metadata = {
  subjectuniqueidentifier_url: "https://api.example.com",
  not_before: "2025-01-01T00:00:00Z",
  not_after: "2026-01-01T00:00:00Z",
  allowed_cidr: "0.0.0.0/0",
  allowed_iso3166list: '{"allow": ["USA"]}',
  permissioned_routes: '{"routes": {...}}',
  max_requests: "1000",
  maxrq_window: "3600",
  jwt_duration: "3600",
  webhook_url: "https://webhook.example.com",
  webhook_cidr: "10.0.0.0/8",
  serviceprovider_id: "bc=near.org;sc=provider.near;id=...",
  serviceprovider_signature: "base64signature..."
};
```

### Utility Functions

```javascript
import {
  calculateCanonicalHash,
  canonicalizeObject,
  base64ToBase64Url,
  base64url2jwk_public_key,
  jwtVerify_fe,
  verifyRoditSignature,
  validateBufferIntegrity,
  verifyHashInputs,
  bufferUtils,
  debugWithType,
  validateAndSetUrl,
  validateAndSetDate,
  validateAndSetJson,
  validateAndSetSignature,
  validateSignatureFormat,
  validatePublicKeyFormat
} from '@rodit/rodit-auth-fe';
```

#### `calculateCanonicalHash(obj)`

Creates a deterministic hash of an object for verification purposes.

#### `base64ToBase64Url(base64)`

Converts standard Base64 to URL-safe Base64.

#### `jwtVerify_fe(token, publicKeyJwk)`

Verifies JWT token signature using a JWK public key (browser-compatible).

#### `verifyRoditSignature(message, signature, publicKey)`

Verifies Ed25519 signature using tweetnacl.

### Logger

```javascript
import { logger, createLogContext } from '@rodit/rodit-auth-fe';

logger.debug('Debug message', { component: 'MyComponent', data: {...} });
logger.info('Info message', { component: 'MyComponent' });
logger.warn('Warning message', { component: 'MyComponent' });
logger.error('Error message', { component: 'MyComponent', error });
```

## State Management

The SDK includes a `stateManager` for managing authentication state:

```javascript
import { stateManager } from '@rodit/rodit-auth-fe';

// Set own RODiT configuration
stateManager.setConfigOwnRodit({
  own_rodit: {
    token_id: "...",
    owner_id: "...",
    metadata: {...}
  }
});

// Get configuration
const config = stateManager.getConfigOwnRodit();
```

## RODiT Token Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `subjectuniqueidentifier_url` | string | API endpoint base URL |
| `not_before` | ISO 8601 | Token validity start date |
| `not_after` | ISO 8601 | Token expiration date |
| `allowed_cidr` | string | Comma-separated CIDR ranges for allowed client IPs |
| `allowed_iso3166list` | JSON string | Allowed country codes: `{"allow": ["USA", "CAN"]}` |
| `permissioned_routes` | JSON string | Route permissions and rate limits |
| `max_requests` | string | Maximum requests per time window |
| `maxrq_window` | string | Rate limit time window in seconds |
| `jwt_duration` | string | JWT token lifetime in seconds |
| `webhook_url` | string | Webhook notification endpoint |
| `webhook_cidr` | string | CIDR ranges for webhook server IPs |
| `serviceprovider_id` | string | Service provider's RODiT ID |
| `serviceprovider_signature` | string | Service provider's signature |
| `openapijson_url` | string | OpenAPI specification URL |
| `userselected_dn` | string | User-selected display name |

## Usage in mintserverapi-rodit

This SDK is used in the RODiT Server Mint application for:

1. **User Authentication**: Authenticating users via NEAR wallet with NEP-413 signatures
2. **RODiT Minting**: Verifying RODiT ownership before minting new server RODiT tokens
3. **API Communication**: Making authenticated requests to the SignSanctum API
4. **Token Verification**: Validating RODiT tokens and their metadata

### Example from mintserverapi-rodit

```javascript
// From src/index.js
import { RoditAuthService } from "@rodit/rodit-auth-fe";

const wallet = new Wallet({
  createAccessKeyFor: process.env.REACT_APP_NEAR_CONTRACT_ID,
  network: "mainnet"
});

const roditAuth = new RoditAuthService(
  wallet,
  process.env.REACT_APP_SIGNAPIENDPOINT,
  window.location.origin,
  process.env.REACT_APP_NEAR_CONTRACT_ID,
  process.env.REACT_APP_NEAR_RPC_URL
);

// Used in Contract class for minting operations
await roditAuth.login_server_withnep413({
  callbackUrl: `${window.location.origin}/login`
});
```

## Security Considerations

### Cryptographic Security

- **Nonce Generation**: Uses `window.crypto.getRandomValues()` for secure random nonce generation
- **HTTPS Required**: Cryptographic operations require HTTPS context on main
- **Ed25519 Signatures**: All RODiT ownership verification uses Ed25519 cryptography
- **JWT Tokens**: Session tokens are JWT-based with automatic expiration and refresh

### Browser Limitations

- **DNS Verification Skipped**: DNS TXT record verification not possible in browser. For full DNS verification, use [`@rodit/rodit-auth-be`](https://www.npmjs.com/package/@rodit/rodit-auth-be) on the server-side.
- **No Node.js Support**: This package is browser-only and does not support Node.js `require()`. Use [`@rodit/rodit-auth-be`](https://www.npmjs.com/package/@rodit/rodit-auth-be) for Node.js environments.

## Environment Variables

Required environment variables for mintserverapi-rodit:

```bash
REACT_APP_NEAR_CONTRACT_ID=your-contract.near
REACT_APP_SIGNAPIENDPOINT=https://api.example.com
REACT_APP_NEAR_RPC_URL=https://rpcnear.org
```

## Dependencies

- `bs58` - Base58 encoding/decoding
- `jwt-decode` - JWT token decoding
- `tweetnacl` - Ed25519 cryptography
- `tweetnacl-util` - Utility functions for tweetnacl
- `ulid` - ULID generation for request tracking

## Package Information

- **Name**: `@rodit/rodit-auth-fe`
- **Version**: 3.0.6
- **License**: UNLICENSED
- **Repository**: https://github.com/discernible-io/rodit-auth-fe
- **Node Version**: >=20.0.0

## Related Packages

- **[@rodit/rodit-auth-be](https://www.npmjs.com/package/@rodit/rodit-auth-be)** - Backend/Node.js version with full DNS verification and server-side features

## Testing

Run the test suite:

```bash
npm test
```

## License

UNLICENSED - Copyright (c) 2026 Discernible IO. All rights reserved.

---

[discernible.io](https://www.discernible.io) · [identyclaw-agents](https://github.com/discernible-io/identyclaw-agents) · [discernible-io](https://github.com/discernible-io)
