# pied-caddy-build

A collection of organization-built plugins for the [Caddy HTTP server](https://caddyserver.com/). Currently includes the `hmac_auth` middleware for HMAC-SHA256 signature authentication.

This project is designed to be extensible, allowing for the addition of new Caddy plugins in the future while maintaining a unified build and release process.

## Project Structure

```
pied-caddy-build/
├── main.go             # Caddy entrypoint with plugin imports
├── Makefile            # Build targets for cross-platform compilation
├── go.mod              # Go module definition
├── plugins/
│   └── hmac-auth/      # HMAC authentication plugin
│       ├── handler.go  # Plugin implementation
│       └── README.md   # Plugin documentation
├── .github/workflows/  # CI/CD automation
└── README.md           # Project documentation
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

For detailed documentation, configuration examples, client implementations, and security considerations, see [plugins/hmac-auth/README.md](plugins/hmac-auth/README.md).

## Adding New Plugins

To add a new plugin to pied-caddy-build:

1. Create a new directory under `plugins/` with your plugin name:
   ```bash
   mkdir -p plugins/my-plugin
   ```

2. Implement your Caddy plugin in the new directory. Make sure to register it with Caddy's module system in an `init()` function.

3. Add an import in [main.go](main.go) to register your plugin:
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
