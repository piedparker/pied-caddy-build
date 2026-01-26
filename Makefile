.PHONY: build build-linux build-darwin build-all install-xcaddy clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  make build-linux      - Build for Linux ARM64"
	@echo "  make build-darwin     - Build for Darwin (macOS) ARM64"
	@echo "  make build-all        - Build for all platforms"
	@echo "  make install-xcaddy   - Install xcaddy"
	@echo "  make clean            - Remove built binaries"
	@echo "  make help             - Show this help message"

# Install xcaddy if not already installed
install-xcaddy:
	@command -v xcaddy >/dev/null 2>&1 || go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	@echo "xcaddy is ready"

# Build for Linux ARM64
build-linux: install-xcaddy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 xcaddy build \
		--with github.com/piedparker/pied-caddy-build=./ \
		--output caddy-linux-arm64

# Build for Darwin (macOS) ARM64
build-darwin: install-xcaddy
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 xcaddy build \
		--with github.com/piedparker/pied-caddy-build=./ \
		--output caddy-darwin-arm64

# Build for all platforms
build-all: build-linux build-darwin
	@echo "Build complete. Binaries:"
	@ls -lh caddy-linux-arm64 caddy-darwin-arm64 2>/dev/null || echo "No binaries found"

# Clean up built binaries
clean:
	rm -f caddy-linux-arm64 caddy-darwin-arm64
	@echo "Cleaned up binaries"
