# HMAC Authentication Plugin for Caddy

A robust HMAC-SHA256 signature authentication middleware for [Caddy HTTP server](https://caddyserver.com/). This plugin provides cryptographic request validation with replay attack protection.

## Features

- **HMAC-SHA256 Signature Verification**: Validates request signatures using shared secrets
- **Timestamp-Based Replay Protection**: Configurable time window to prevent timestamp-based replay attacks
- **Request ID (Nonce) Validation**: Tracks and prevents nonce reuse with TTL-based expiration
- **Efficient In-Memory Cache**: Nonce cache with automatic garbage collection to prevent memory bloat
- **Header Stripping**: Removes authentication headers before passing requests to upstream services
- **Constant-Time Comparison**: Uses `crypto/subtle` to prevent timing-based signature attacks

## Installation

This plugin is built as part of the `pied-caddy-build` project. It's compiled into the Caddy binary during the build process.

## Configuration

### Caddyfile Syntax

```caddyfile
hmac_auth {
    secret <your-secret-key>
    [window <duration>]
    [nonce_ttl <duration>]
}
```

### Configuration Options

- **secret** (required): The shared secret key used for HMAC signature generation and verification
- **window** (optional): The acceptable time window for requests in seconds. Defaults to `60s`
- **nonce_ttl** (optional): Time-to-live for nonce entries in the cache. Defaults to `5m`

### Example Configuration

```caddyfile
example.com {
  hmac_auth {
    secret "my-secret-key-12345"
    window 60s
    nonce_ttl 5m
  }
  reverse_proxy localhost:8080
}
```

## Request Signature Format

Clients must include the following headers in their requests:

- **X-Timestamp**: Unix epoch timestamp (seconds) of the request
- **X-Request-ID**: Unique request identifier (nonce) to prevent replay attacks
- **X-Signature**: Base64URL-encoded HMAC-SHA256 signature

### Signature Computation

The signature is computed over a canonical message format:

```
{METHOD}\n{PATH}?{QUERY}\n{TIMESTAMP}\n{NONCE}
```

Example for `GET /api/endpoint?param=value`:

```
GET
/api/endpoint?param=value
1706500000
request-nonce-12345
```

Then HMAC-SHA256 is applied with the shared secret, and the result is Base64URL-encoded.

### Client Example (JavaScript)

```javascript
import crypto from 'crypto';

const secret = 'my-secret-key-12345';
const method = 'GET';
const path = '/api/endpoint';
const query = 'param=value';
const timestamp = Math.floor(Date.now() / 1000).toString();
const nonce = crypto.randomUUID();

const canonical = `${method}\n${path}${query ? '?' + query : ''}\n${timestamp}\n${nonce}`;
const signature = crypto
  .createHmac('sha256', secret)
  .update(canonical)
  .digest('base64url');

const headers = {
  'X-Timestamp': timestamp,
  'X-Request-ID': nonce,
  'X-Signature': signature,
};

const response = await fetch(`http://example.com${path}${query ? '?' + query : ''}`, {
  method,
  headers,
});
```

### Client Example (Python)

```python
import hmac
import hashlib
import base64
import time
import uuid
from urllib.parse import urlencode

secret = 'my-secret-key-12345'
method = 'GET'
path = '/api/endpoint'
params = {'param': 'value'}
timestamp = str(int(time.time()))
nonce = str(uuid.uuid4())

query = urlencode(params) if params else ''
canonical = f'{method}\n{path}{("?" + query) if query else ""}\n{timestamp}\n{nonce}'

signature = base64.urlsafe_b64encode(
    hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).digest()
).decode().rstrip('=')

headers = {
    'X-Timestamp': timestamp,
    'X-Request-ID': nonce,
    'X-Signature': signature,
}

url = f'http://example.com{path}{"?" + query if query else ""}'
response = requests.get(url, headers=headers)
```

## Error Responses

The middleware returns HTTP 403 Forbidden with descriptive error messages:

- **missing auth headers**: One or more required headers (`X-Timestamp`, `X-Request-ID`, `X-Signature`) are missing
- **invalid timestamp**: The `X-Timestamp` value is not a valid integer
- **timestamp outside window**: The request timestamp is outside the configured time window
- **replayed nonce**: The nonce has already been used within the TTL period
- **bad signature**: The provided signature does not match the computed signature

## Security Considerations

1. **Secret Management**: Store secrets securely using Caddy's [secrets management](https://caddyserver.com/docs/conventions#secrets) or environment variables
2. **HTTPS Only**: Always use HTTPS in production to prevent header interception
3. **Time Synchronization**: Ensure client and server clocks are reasonably synchronized (within the configured window)
4. **Nonce Uniqueness**: Each request must include a unique nonce; reused nonces are rejected
5. **Replay Window**: The `window` parameter controls how far apart client and server clocks can be; balance this against replay attack risk

## Performance

- **O(1) Nonce Lookup**: Constant-time nonce checking using a hash map
- **Automatic GC**: Cache garbage collection triggers when size exceeds 20,000 entries
- **Low Overhead**: HMAC-SHA256 computation is performed only once per request

## License

This project is licensed under the Apache License, Version 2.0. See the LICENSE file at the root of the `pied-caddy-build` repository for details.

```
Copyright 2026 pied-caddy-build contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Contributing

For information on contributing to this plugin, see the main [pied-caddy-build](https://github.com/piedparker/pied-caddy-build) repository.
