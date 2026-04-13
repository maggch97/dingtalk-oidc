# DingTalk -> OIDC Bridge (Minimal)

This service provides a minimal OpenID Connect layer in front of DingTalk. It performs the standard Authorization Code flow (browser redirect -> DingTalk -> callback -> OIDC code -> token) and issues an ID Token containing basic DingTalk user info. A UserInfo endpoint is now available.

## Features
- Standard OIDC Authorization Code flow.
- `/authorize` starts flow and redirects user to DingTalk.
- `/dingtalk/callback` (internal) receives DingTalk `code` and creates OIDC authorization code.
- `/token` exchanges OIDC authorization code for ID Token (reused as access token).
- `/userinfo` returns profile claims extracted from the token (sub, name, email, phone_number if present).
- Discovery: `/.well-known/openid-configuration` with `userinfo_endpoint` + `/jwks.json` for keys.
- ID Token claims: `iss, sub, aud, exp, iat, nonce (if provided), name, email, phone_number`.
- In‑memory auth code + pending state stores (5/10 min TTL) and ephemeral RSA key.

## NOT Production Ready
- No TLS termination (use a reverse proxy or enable TLS yourself).
- Ephemeral signing key (losing continuity for long‑lived sessions).
- Auth codes & tokens only in memory; not horizontally scalable.

## Environment Variables
| Variable | Description |
|----------|-------------|
| `ISSUER` | Public base URL of this service (e.g. `https://oidc.example.com`). |
| `DINGTALK_CLIENT_ID` | DingTalk App Key. |
| `DINGTALK_CLIENT_SECRET` | DingTalk App Secret. |
| `ADDRESS` | (Optional) Listen address, default `:8086`. |
| `ALLOWED_REDIRECT_URLS` | Comma-separated list of allowed redirect URLs. Example: `http://localhost:3000/callback,https://app.example.com/auth/callback` |
| `CLAIMS_TRANSFORM_SCRIPT` | (Optional) Path to JavaScript file to transform claims before signing the ID token. Must define a `transform(claims, context)` function that returns modified claims. See [Claims Transformation](#claims-transformation) section. |

## Claims Transformation

You can customize the ID token claims using JavaScript before they are signed. This is useful for:
- Adding custom groups/roles based on user attributes
- Mapping DingTalk user info to your application's schema
- Adding organization-specific metadata
- Conditional claim injection

### Usage

1. Create a JavaScript file (e.g., `transform.js`) with a `transform(claims, context)` function
2. Set the `CLAIMS_TRANSFORM_SCRIPT` environment variable to the file path
3. Mount the file as a volume when using Docker

**Example transform.js:**
```javascript
function transform(claims, context) {
    // Add custom fields
    if (claims.email && claims.email.endsWith('@example.com')) {
        claims.groups = ['admin', 'users'];
        claims.role = 'admin';
    } else {
        claims.groups = ['users'];
        claims.role = 'user';
    }
    
    claims.organization = 'MyCompany';

    if (context && context.redirect_uri) {
        claims.redirect_uri = context.redirect_uri;
    }
    
    // IMPORTANT: Always return the claims object
    return claims;
}
```

**Local usage:**
```bash
export CLAIMS_TRANSFORM_SCRIPT="./transform.js"
go run ./cmd/server
```

**Docker usage:**
```yaml
services:
  oidc:
    image: maggch/dingtalk-oidc:latest
    environment:
      CLAIMS_TRANSFORM_SCRIPT: "/app/config/transform.js"
    volumes:
      - ./transform.js:/app/config/transform.js:ro
```

### Example

See `example-transform.js` for a comprehensive example showing various transformation patterns.

### Available Claims

The `claims` object passed to your transform function includes:
- `iss` - Issuer URL
- `sub` - Subject (DingTalk UnionID)
- `aud` - Audience (client ID)
- `iat` - Issued at timestamp
- `exp` - Expiration timestamp
- `nonce` - Nonce (if provided in auth request)
- `name` - User's display name (if available)
- `picture` - Avatar URL (if available)
- `email` - Email address (if available)
- `email_verified` - Email verification status
- `phone_number` - Mobile number (if available)
- `phone_number_verified` - Phone verification status

The `context` object passed as the second argument currently includes:
- `redirect_uri` - Original OIDC client `redirect_uri` from `/authorize`
- `callback_url` - Alias of `redirect_uri` for compatibility with existing wording

### Notes

- If `CLAIMS_TRANSFORM_SCRIPT` is not set, claims are used as-is
- Script errors will cause token generation to fail with HTTP 500
- The transform function runs in a sandboxed JavaScript VM using [goja](https://github.com/dop251/goja)
- Keep scripts simple and fast to avoid performance issues

## Flow Diagram
```
Client Browser --> /authorize (OIDC)
	OIDC -> redirect to DingTalk authorize
	User logs in DingTalk
DingTalk -> /dingtalk/callback (OIDC) with code
	OIDC exchanges DingTalk code -> user info -> issues OIDC auth code
OIDC -> redirect back to client with code
Client -> /token -> ID Token (+ access token same value)
Client -> /userinfo (optional) with Bearer token
```

## Example Authorize Request
```
GET /authorize?client_id=YOUR_CLIENT_ID&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid%20email%20profile&state=xyz&nonce=abc
```

## Example Token Request
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=RETURNED_CODE&client_id=YOUR_CLIENT_ID&client_secret=YOUR_SECRET
```

## Running
```bash
export ISSUER="http://localhost:8086"
export DINGTALK_CLIENT_ID="your_dt_app_key"
export DINGTALK_CLIENT_SECRET="your_dt_app_secret"
go run ./cmd/server
```

Then visit:
- Discovery: `http://localhost:8086/.well-known/openid-configuration`
- UserInfo (example):
	```bash
	curl -H "Authorization: Bearer <ID_TOKEN>" http://localhost:8086/userinfo
	```

## Docker Build & Publish

### Local Build
```bash
docker build -t dingtalk-oidc:local .
docker run --rm -p 8086:8086 \
	-e ISSUER="http://localhost:8086" \
	-e DINGTALK_CLIENT_ID="your_dt_app_key" \
	-e DINGTALK_CLIENT_SECRET="your_dt_app_secret" \
	dingtalk-oidc:local
```

### GitHub Actions (Docker Hub)
A workflow at `.github/workflows/docker-publish.yml` builds multi-arch images (amd64, arm64) only for semantic version tags (`v*.*.*`).

Set repository secrets:
| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | A Docker Hub access token / password |

Image tags produced per release tag:
- Semantic tag (e.g. `v1.2.3`)
- `latest` (always updated to newest release)
- Commit SHA short

Pull example:
```bash
docker pull $DOCKERHUB_USERNAME/dingtalk-oidc:latest
```

## Automatic Version Bumping
An automatic version bump workflow (`auto-version.yml`) analyzes commit messages on pushes to `main` using simple Conventional Commit rules:

| Pattern | Effect |
|---------|--------|
| `BREAKING CHANGE:` footer or `type!:` | Major bump |
| `feat:` | Minor bump (unless major already) |
| `fix:, perf:, refactor:, chore:, docs:, test:` | Patch bump (if no higher) |
| No matching commits | Skip (no new tag) |

Script: `scripts/next_version.py` (outputs next `vX.Y.Z`). First bump starts from `v0.0.0`.

Disable temporarily: mark commits without conventional prefixes; no tag will be created.
Force manual: create and push your own `vX.Y.Z` tag (workflow will ignore since ref is a tag).

## Next Steps / Ideas
- Persist signing key & rotation strategy.
- (DONE) Add `/userinfo` endpoint.
- Support Refresh Tokens.
- Multi-client registration + dynamic client metadata.
- Structured logging & metrics.

---
Generated initial minimal implementation. Improve as needed for production.
