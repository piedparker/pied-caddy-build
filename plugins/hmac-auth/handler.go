// Copyright 2026 pied-caddy-build contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	headerTimestamp = "X-Timestamp"
	headerNonce     = "X-Request-ID"
	headerSignature = "X-Signature"
)

func init() {
	caddy.RegisterModule(HMACMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("hmac_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("hmac_auth", httpcaddyfile.Before, "reverse_proxy")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m HMACMiddleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}

type HMACMiddleware struct {
	Secret   string         `json:"secret,omitempty"`
	Window   caddy.Duration `json:"window,omitempty"`    // e.g. 60s
	NonceTTL caddy.Duration `json:"nonce_ttl,omitempty"` // e.g. 5m

	cache *nonceCache
}

type nonceCache struct {
	mu   sync.Mutex
	seen map[string]int64
	ttl  int64
}

func newNonceCache(ttl time.Duration) *nonceCache {
	return &nonceCache{
		seen: make(map[string]int64),
		ttl:  int64(ttl.Seconds()),
	}
}

func (c *nonceCache) checkAndStore(nonce string, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// GC occasionally
	if len(c.seen) > 20000 {
		for k, exp := range c.seen {
			if exp <= now {
				delete(c.seen, k)
			}
		}
	}

	if exp, ok := c.seen[nonce]; ok && exp > now {
		return false
	}
	c.seen[nonce] = now + c.ttl
	return true
}

// Caddy module info
func (HMACMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hmac_auth",
		New: func() caddy.Module { return new(HMACMiddleware) },
	}
}

// Provision runs after config is loaded
func (m *HMACMiddleware) Provision(ctx caddy.Context) error {
	if m.Secret == "" {
		return fmt.Errorf("hmac_auth: secret is required")
	}
	if m.Window == 0 {
		m.Window = caddy.Duration(60 * time.Second)
	}
	if m.NonceTTL == 0 {
		m.NonceTTL = caddy.Duration(5 * time.Minute)
	}
	m.cache = newNonceCache(time.Duration(m.NonceTTL))
	return nil
}

func (m HMACMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ts := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	sig := r.Header.Get(headerSignature)

	if ts == "" || nonce == "" || sig == "" {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("missing auth headers"))
	}

	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid timestamp"))
	}

	now := time.Now().Unix()
	windowSec := int64(time.Duration(m.Window).Seconds())
	if int64(math.Abs(float64(now-tsInt))) > windowSec {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("timestamp outside window"))
	}

	if !m.cache.checkAndStore(nonce, now) {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("replayed nonce"))
	}

	pathWithQuery := r.URL.Path
	if r.URL.RawQuery != "" {
		pathWithQuery += "?" + r.URL.RawQuery
	}
	canon := fmt.Sprintf("%s\n%s\n%s\n%s", r.Method, pathWithQuery, ts, nonce)

	expected := hmacSHA256([]byte(m.Secret), canon)
	got, err := base64urlDecode(sig)
	if err != nil || !constantTimeEqual(expected, got) {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("bad signature"))
	}

	// Strip headers before upstream sees them
	r.Header.Del(headerTimestamp)
	r.Header.Del(headerNonce)
	r.Header.Del(headerSignature)

	return next.ServeHTTP(w, r)
}

func hmacSHA256(secret []byte, msg string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func base64urlDecode(s string) ([]byte, error) {
	// accept unpadded
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// Caddyfile support
func (m *HMACMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Secret = d.Val()

			case "window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				m.Window = caddy.Duration(dur)
			case "nonce_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				m.NonceTTL = caddy.Duration(dur)
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var _ caddyhttp.MiddlewareHandler = (*HMACMiddleware)(nil)
var _ caddy.Provisioner = (*HMACMiddleware)(nil)
var _ caddyfile.Unmarshaler = (*HMACMiddleware)(nil)
