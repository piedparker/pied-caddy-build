package piedcaddybuild

// This file serves as the module registry for pied-caddy-build.
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
	// hmac_auth plugin - HMAC-SHA256 signature authentication middleware
	_ "github.com/piedparker/pied-caddy-build/plugins/hmac-auth"
)

// Plugins imported above are automatically initialized and registered
// with the Caddy server when this module is imported by xcaddy's generated main.
