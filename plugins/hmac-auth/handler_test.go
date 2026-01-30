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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestProvision tests the Provision method
func TestProvision(t *testing.T) {
	tests := []struct {
		name    string
		m       *HMACMiddleware
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			m: &HMACMiddleware{
				Secret: "test-secret",
			},
			wantErr: false,
		},
		{
			name: "missing secret",
			m: &HMACMiddleware{
				Secret: "",
			},
			wantErr: true,
			errMsg:  "secret is required",
		},
		{
			name: "default window",
			m: &HMACMiddleware{
				Secret: "test-secret",
				Window: 0,
			},
			wantErr: false,
		},
		{
			name: "default nonce TTL",
			m: &HMACMiddleware{
				Secret:   "test-secret",
				NonceTTL: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := caddy.Context{}
			err := tt.m.Provision(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provision() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Provision() error = %v, want error containing %q", err, tt.errMsg)
			}
			if !tt.wantErr {
				if tt.m.cache == nil {
					t.Error("Provision() cache not initialized")
				}
				if tt.m.Window == 0 {
					t.Error("Provision() Window not set to default")
				}
				if tt.m.NonceTTL == 0 {
					t.Error("Provision() NonceTTL not set to default")
				}
			}
		})
	}
}

// TestHMACAuth_ValidRequest tests a valid authenticated request
func TestHMACAuth_ValidRequest(t *testing.T) {
	secret := "test-secret-key"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-1"
	method := "GET"
	path := "/api/endpoint"

	// Compute signature
	canonical := fmt.Sprintf("%s\n%s\n%s\n%s", method, path, timestamp, nonce)
	sig := base64.URLEncoding.EncodeToString(
		hmacSHA256([]byte(secret), canonical),
	)

	m := &HMACMiddleware{
		Secret: secret,
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Create request
	req := httptest.NewRequest(method, "http://example.com"+path, nil)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, sig)

	// Mock next handler
	called := false
	next := func(w http.ResponseWriter, r *http.Request) error {
		called = true
		// Verify headers were stripped
		if r.Header.Get(headerTimestamp) != "" {
			t.Error("Timestamp header not stripped")
		}
		if r.Header.Get(headerNonce) != "" {
			t.Error("Nonce header not stripped")
		}
		if r.Header.Get(headerSignature) != "" {
			t.Error("Signature header not stripped")
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, mockHandler(next))
	if err != nil {
		t.Errorf("ServeHTTP() error = %v, want nil", err)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

// TestHMACAuth_InvalidSignature tests rejection of invalid signature
func TestHMACAuth_InvalidSignature(t *testing.T) {
	secret := "test-secret-key"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-2"
	method := "GET"
	path := "/api/endpoint"

	m := &HMACMiddleware{
		Secret: secret,
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest(method, "http://example.com"+path, nil)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, "invalid-signature")

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, mockHandler(nil))
	if err == nil {
		t.Error("ServeHTTP() expected error for invalid signature, got nil")
	}
}

// TestHMACAuth_MissingHeaders tests rejection when headers are missing
func TestHMACAuth_MissingHeaders(t *testing.T) {
	m := &HMACMiddleware{
		Secret: "test-secret",
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "missing timestamp",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.com/", nil)
				r.Header.Set(headerNonce, "nonce")
				r.Header.Set(headerSignature, "sig")
				return r
			}(),
		},
		{
			name: "missing nonce",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.com/", nil)
				r.Header.Set(headerTimestamp, "123")
				r.Header.Set(headerSignature, "sig")
				return r
			}(),
		},
		{
			name: "missing signature",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.com/", nil)
				r.Header.Set(headerTimestamp, "123")
				r.Header.Set(headerNonce, "nonce")
				return r
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			err := m.ServeHTTP(w, tt.req, mockHandler(nil))
			if err == nil {
				t.Error("ServeHTTP() expected error, got nil")
			}
		})
	}
}

// TestHMACAuth_InvalidTimestamp tests rejection of non-integer timestamp
func TestHMACAuth_InvalidTimestamp(t *testing.T) {
	m := &HMACMiddleware{
		Secret: "test-secret",
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set(headerTimestamp, "not-a-number")
	req.Header.Set(headerNonce, "nonce")
	req.Header.Set(headerSignature, "sig")

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, mockHandler(nil))
	if err == nil {
		t.Error("ServeHTTP() expected error for invalid timestamp, got nil")
	}
}

// TestHMACAuth_TimestampOutsideWindow tests rejection of timestamp outside window
func TestHMACAuth_TimestampOutsideWindow(t *testing.T) {
	secret := "test-secret-key"
	nonce := "unique-nonce-3"
	method := "GET"
	path := "/api/endpoint"

	m := &HMACMiddleware{
		Secret: secret,
		Window: caddy.Duration(60 * time.Second),
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Use timestamp way in the past
	oldTimestamp := strconv.FormatInt(time.Now().Unix()-200, 10)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%s", method, path, oldTimestamp, nonce)
	sig := base64.URLEncoding.EncodeToString(
		hmacSHA256([]byte(secret), canonical),
	)

	req := httptest.NewRequest(method, "http://example.com"+path, nil)
	req.Header.Set(headerTimestamp, oldTimestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, sig)

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, mockHandler(nil))
	if err == nil {
		t.Error("ServeHTTP() expected error for timestamp outside window, got nil")
	}
}

// TestHMACAuth_ReplayedNonce tests rejection of reused nonce
func TestHMACAuth_ReplayedNonce(t *testing.T) {
	secret := "test-secret-key"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-4"
	method := "GET"
	path := "/api/endpoint"

	canonical := fmt.Sprintf("%s\n%s\n%s\n%s", method, path, timestamp, nonce)
	sig := base64.URLEncoding.EncodeToString(
		hmacSHA256([]byte(secret), canonical),
	)

	m := &HMACMiddleware{
		Secret: secret,
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// First request with the nonce should succeed
	req1 := httptest.NewRequest(method, "http://example.com"+path, nil)
	req1.Header.Set(headerTimestamp, timestamp)
	req1.Header.Set(headerNonce, nonce)
	req1.Header.Set(headerSignature, sig)

	w1 := httptest.NewRecorder()
	err1 := m.ServeHTTP(w1, req1, mockHandler(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err1 != nil {
		t.Errorf("First request failed: %v", err1)
	}

	// Second request with the same nonce should fail
	req2 := httptest.NewRequest(method, "http://example.com"+path, nil)
	req2.Header.Set(headerTimestamp, timestamp)
	req2.Header.Set(headerNonce, nonce)
	req2.Header.Set(headerSignature, sig)

	w2 := httptest.NewRecorder()
	err2 := m.ServeHTTP(w2, req2, mockHandler(nil))
	if err2 == nil {
		t.Error("Second request with replayed nonce should fail, but succeeded")
	}
}

// TestHMACAuth_WithQueryString tests signature verification with query parameters
func TestHMACAuth_WithQueryString(t *testing.T) {
	secret := "test-secret-key"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-5"
	method := "GET"
	path := "/api/endpoint"
	query := "param=value&other=test"

	// Include query string in canonical message
	canonical := fmt.Sprintf("%s\n%s?%s\n%s\n%s", method, path, query, timestamp, nonce)
	sig := base64.URLEncoding.EncodeToString(
		hmacSHA256([]byte(secret), canonical),
	)

	m := &HMACMiddleware{
		Secret: secret,
	}
	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest(method, "http://example.com"+path+"?"+query, nil)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, sig)

	called := false
	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, mockHandler(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Errorf("ServeHTTP() error = %v, want nil", err)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

// TestBase64urlDecode tests URL-safe base64 decoding
func TestBase64urlDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "padded",
			input:   base64.URLEncoding.EncodeToString([]byte("test")),
			wantErr: false,
		},
		{
			name:    "unpadded (2 chars missing)",
			input:   strings.TrimRight(base64.URLEncoding.EncodeToString([]byte("test")), "="),
			wantErr: false,
		},
		{
			name:    "invalid base64",
			input:   "!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := base64urlDecode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64urlDecode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestUnmarshalCaddyfile tests Caddyfile parsing
func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantSecret string
	}{
		{
			name: "valid config",
			input: `hmac_auth {
				secret my-secret
				window 120s
				nonce_ttl 10m
			}`,
			wantErr:    false,
			wantSecret: "my-secret",
		},
		{
			name: "minimal config",
			input: `hmac_auth {
				secret minimal-secret
			}`,
			wantErr:    false,
			wantSecret: "minimal-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			m := &HMACMiddleware{}
			err := m.UnmarshalCaddyfile(d)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			
			if !tt.wantErr && m.Secret != tt.wantSecret {
				t.Errorf("UnmarshalCaddyfile() Secret = %q, want %q", m.Secret, tt.wantSecret)
			}
		})
	}
}

// TestConstantTimeEqual tests constant-time comparison
func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name  string
		a     []byte
		b     []byte
		equal bool
	}{
		{
			name:  "equal",
			a:     []byte("test"),
			b:     []byte("test"),
			equal: true,
		},
		{
			name:  "different",
			a:     []byte("test"),
			b:     []byte("fail"),
			equal: false,
		},
		{
			name:  "different length",
			a:     []byte("test"),
			b:     []byte("testing"),
			equal: false,
		},
		{
			name:  "empty",
			a:     []byte(""),
			b:     []byte(""),
			equal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := constantTimeEqual(tt.a, tt.b)
			if result != tt.equal {
				t.Errorf("constantTimeEqual() = %v, want %v", result, tt.equal)
			}
		})
	}
}

// TestNonceCache tests the nonce cache functionality
func TestNonceCache(t *testing.T) {
	ttl := time.Duration(5 * time.Second)
	cache := newNonceCache(ttl)

	now := time.Now().Unix()

	// First store should succeed
	if !cache.checkAndStore("nonce-1", now) {
		t.Error("First checkAndStore should return true")
	}

	// Replay should fail
	if cache.checkAndStore("nonce-1", now) {
		t.Error("Replayed nonce should return false")
	}

	// Different nonce should succeed
	if !cache.checkAndStore("nonce-2", now) {
		t.Error("Different nonce should return true")
	}

	// Expired nonce should be allowed again
	expiredNow := now + 10
	if !cache.checkAndStore("nonce-1", expiredNow) {
		t.Error("Expired nonce should be allowed again")
	}
}

// mockHandler creates a mock caddyhttp.Handler
func mockHandler(fn func(w http.ResponseWriter, r *http.Request) error) caddyhttp.Handler {
	return testHandler{fn: fn}
}

// Helper to satisfy interface - implements caddyhttp.Handler
type testHandler struct {
	fn func(w http.ResponseWriter, r *http.Request) error
}

func (h testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if h.fn != nil {
		return h.fn(w, r)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestCaddyModule(t *testing.T) {
	m := HMACMiddleware{}
	info := m.CaddyModule()
	
	if info.ID != "http.handlers.hmac_auth" {
		t.Errorf("CaddyModule() ID = %q, want %q", info.ID, "http.handlers.hmac_auth")
	}
	
	if info.New == nil {
		t.Error("CaddyModule() New function is nil")
	}
}
