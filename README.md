# pied-caddy-build

A collection of organization-built plugins for the [Caddy HTTP server](https://caddyserver.com/). Currently includes the `hmac_auth` middleware for HMAC-SHA256 signature authentication.

This project is designed to be extensible, allowing for the addition of new Caddy plugins in the future while maintaining a unified build and release process.

## Project Structure

```
pied-caddy-build/
├── cmd/
│   └── caddy/          # Caddy entrypoint with plugin imports
├── plugins/
│   └── hmac-auth/      # HMAC authentication plugin
├── .github/workflows/  # CI/CD automation
└── README.md
```

## Plugins

### hmac_auth

HMAC-SHA256 signature authentication middleware for Caddy.

**Features:**
- HMAC-SHA256 signature verification
- Timestamp-based replay protection with configurable time windows
- Request ID (nonce) validation with nonce TTL management
- Automatic header stripping to prevent upstream visibility
- Efficient in-memory nonce cache with periodic garbage collection

**Configuration:**

```caddyfile
{
  http {
    servers {
      :443 {
        protocols h1 h2 h3
      }
    }
  }
}

example.com {
  hmac_auth {
    secret "your-secret-key"
    window 60s
    nonce_ttl 5m
  }
  reverse_proxy localhost:8080
}
```

**Request Requirements:**

Clients must include these headers in each request:
- `X-Timestamp`: Unix timestamp (seconds since epoch)
- `X-Request-ID`: Unique request identifier (nonce)
- `X-Signature`: Base64url-encoded HMAC-SHA256 signature

**Signature Calculation:**

```
canonical_string = METHOD\nPATH[?QUERY]\nTIMESTAMP\nNONCE
signature = base64url(HMAC-SHA256(secret, canonical_string))
```

Example in Python:
```python
import hmac
import hashlib
import base64
from datetime import datetime

secret = "your-secret-key"
method = "GET"
path = "/api/endpoint"
timestamp = str(int(datetime.utcnow().timestamp()))
nonce = "unique-request-id-1234"

canonical = f"{method}\n{path}\n{timestamp}\n{nonce}"
sig = base64.urlsafe_b64encode(
    hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).digest()
).rstrip(b'=').decode()

print(f"X-Signature: {sig}")
```

## Adding New Plugins

To add a new plugin to pied-caddy-build:

1. Create a new directory under `plugins/` with your plugin name:
   ```bash
   mkdir -p plugins/my-plugin
   ```

2. Implement your Caddy plugin in the new directory. Make sure to register it with Caddy's module system in an `init()` function.

3. Add an import in [cmd/caddy/main.go](cmd/caddy/main.go) to register your plugin:
   ```go
   import _ "github.com/piedparker/pied-caddy-build/plugins/my-plugin"
   ```

4. Update this README with documentation for your new plugin.

## Building

### Building Locally

Ensure you have [Go 1.25+](https://golang.org/dl/) installed, then:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/piedparker/pied-caddy-build=./
```

The resulting `caddy` binary will include all registered plugins.

### Building for Different Platforms

```bash
# Linux ARM64
GOOS=linux GOARCH=arm64 xcaddy build --with github.com/piedparker/pied-caddy-build=./

# macOS ARM64
GOOS=darwin GOARCH=arm64 xcaddy build --with github.com/piedparker/pied-caddy-build=./
```

## Releases

Releases are automatically created when version tags are pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The GitHub Actions workflow will build Caddy binaries with all plugins for supported platforms and create a release.

## Development

### Running Tests

```bash
go test ./...
```

### Code Style

This project follows standard Go conventions. Format your code with:

```bash
go fmt ./...
```

## License

Please refer to the individual plugin directories for license information.

## Contributing

Contributions are welcome! To add a new plugin or improve existing ones:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-plugin`)
3. Commit your changes (`git commit -am 'Add my plugin'`)
4. Push to the branch (`git push origin feature/my-plugin`)
5. Open a Pull Request

When contributing a new plugin, please include:
- Implementation in `plugins/{plugin-name}/`
- Documentation in the README
- Basic tests for the plugin functionality
