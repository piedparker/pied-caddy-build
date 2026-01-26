package main

// This file serves as the build entrypoint for pied-caddy-build.
// It imports all plugins to ensure they are registered with Caddy.
//
// To add a new plugin:
// 1. Create a new directory under plugins/ with your plugin code
// 2. Add an import statement below pointing to your plugin package
// 3. Update the Caddyfile configuration to use your new plugin directive
//
// Example:
//   import _ "github.com/piedparker/pied-caddy-build/plugins/my-plugin"

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Import Caddy's standard modules for a complete build
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// hmac_auth plugin - HMAC-SHA256 signature authentication middleware
	_ "github.com/piedparker/pied-caddy-build/plugins/hmac-auth"
)

func main() {
	caddycmd.Main()
}
