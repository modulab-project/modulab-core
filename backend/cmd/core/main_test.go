package main

import "testing"

// isTrustedProxyPeer is duplicated here, in internal/auth, and in
// internal/bootstrap (three independent copies, no shared package - see
// each site's own doc comment) - governs whether X-Forwarded-For is trusted
// for rate-limit bucketing and audit logging at this entry point.
func TestIsTrustedProxyPeer(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"private 10.x", "10.0.0.5", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 192.168.x", "192.168.1.1", true},
		{"public IP rejected", "8.8.8.8", false},
		{"not an IP", "traefik", false},
		{"empty string", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTrustedProxyPeer(tc.host)
			if got != tc.want {
				t.Fatalf("isTrustedProxyPeer(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// isAPIPath decides, ahead of the ServeMux, whether a request goes to the
// API chain or to the embedded SPA. Getting it wrong is quiet in both
// directions: a false negative hands an API path to the SPA handler, which
// answers 200 text/html and makes the caller's res.json() fail on a parse
// error instead of showing the endpoint's real status; a false positive
// sends a frontend route into the mux, which 404s it instead of letting
// React Router resolve it client-side.
//
// The normalisation cases below are the reason this calls path.Clean at
// all - nginx merged duplicate slashes before proxying, so restoring that
// keeps behaviour identical to the pre-embed deployment.
func TestIsAPIPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"healthz", "/healthz", true},
		{"healthz trailing slash", "/healthz/", true},
		{"healthz subpath", "/healthz/sub", true},
		{"healthz is not a prefix match", "/healthzfoo", false},

		{"v1 bare", "/v1", true},
		{"v1 trailing slash", "/v1/", true},
		{"v1 route", "/v1/auth/me", true},
		{"v1 sse", "/v1/events", true},
		{"v1 is not a prefix match", "/v1abc", false},

		// A FrontendBaseURL with a trailing slash produces "//v1/...".
		// Without path.Clean this fell through to the SPA and answered 200.
		{"leading double slash", "//v1/auth/me", true},
		{"interior double slash", "/v1//auth/me", true},
		{"triple slash", "///v1/events", true},
		{"dot-dot resolves into v1", "/../v1/auth/me", true},

		{"root", "/", false},
		{"empty", "", false},
		{"spa deep route", "/settings/deep/route", false},
		{"spa module route", "/modules/my-places", false},
		{"hashed asset", "/assets/index-abc123.js", false},
		{"pwa manifest", "/manifest.webmanifest", false},
		{"service worker", "/sw.js", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAPIPath(tc.path); got != tc.want {
				t.Errorf("isAPIPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
