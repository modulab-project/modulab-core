package auth

import "testing"

// sanitizeReturnPath is the open-redirect guard on LoginHandler's ?return=
// parameter before it is echoed back into redirectToFrontend's URL fragment.
func TestSanitizeReturnPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"simple in-app path", "/dashboard", "/dashboard"},
		{"path with query string", "/modules/recipes?tab=list", "/modules/recipes?tab=list"},
		{"empty string rejected", "", ""},
		{"protocol-relative rejected", "//evil.example", ""},
		{"protocol-relative with path rejected", "//evil.example/phish", ""},
		{"absolute URL rejected (no leading slash)", "https://evil.example", ""},
		{"missing leading slash rejected", "dashboard", ""},
		{"contains space rejected", "/foo bar", ""},
		{"contains tab rejected", "/foo\tbar", ""},
		{"contains newline rejected", "/foo\nbar", ""},
		{"contains carriage return rejected", "/foo\rbar", ""},
		{"over 256 chars rejected", "/" + repeatChar('a', 256), ""},
		{"exactly 256 chars allowed", "/" + repeatChar('a', 255), "/" + repeatChar('a', 255)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeReturnPath(tc.in)
			if got != tc.want {
				t.Fatalf("sanitizeReturnPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// isTrustedProxyPeer decides whether an X-Forwarded-For header is honored at
// all - only ever for a peer inside loopback/private ranges, never a public
// address (which would let any external client spoof their own IP for the
// rate limiter and audit log).
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
		{"public IPv6 rejected", "2001:4860:4860::8888", false},
		{"not an IP at all", "not-an-ip", false},
		{"empty string", "", false},
		{"hostname rejected", "traefik", false},
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

// sessionBaselineChanged is checkSessionCountryAnomaly's and
// checkSessionDeviceAnomaly's (session.go) shared pure decision of whether a
// country/device change is worth flagging: only when both sides are known
// and they actually differ - never on a first-ever check (no baseline yet)
// or when the current request has no CF-IPCountry header/User-Agent at all
// (loginCountry returns "" for local/dev access bypassing Cloudflare),
// since there is nothing meaningful to compare in either case. Cases below
// use country-shaped values, but the function is value-agnostic - the same
// table would hold for User-Agent strings.
func TestSessionBaselineChanged(t *testing.T) {
	cases := []struct {
		name     string
		baseline string
		current  string
		want     bool
	}{
		{"same value - no anomaly", "DE", "DE", false},
		{"different value - anomaly", "DE", "US", true},
		{"no baseline yet - not flagged", "", "US", false},
		{"no current value - not flagged", "DE", "", false},
		{"neither known - not flagged", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sessionBaselineChanged(tc.baseline, tc.current)
			if got != tc.want {
				t.Fatalf("sessionBaselineChanged(%q, %q) = %v, want %v", tc.baseline, tc.current, got, tc.want)
			}
		})
	}
}

// DeriveRole implements spec 3.3's Dynamic Prefix Hard Gate: whichever of
// prefix+"admin"/prefix+"user" appears in the groups claim, admin taking
// priority when a user is somehow in both.
func TestDeriveRole(t *testing.T) {
	const prefix = "modulab_"

	cases := []struct {
		name   string
		groups []string
		prefix string
		want   string
	}{
		{"admin group", []string{"modulab_admin"}, prefix, RoleAdmin},
		{"user group", []string{"modulab_user"}, prefix, RoleUser},
		{"neither group -> pending", []string{"some_other_group"}, prefix, RolePending},
		{"empty groups -> pending", nil, prefix, RolePending},
		{"both groups -> admin wins", []string{"modulab_user", "modulab_admin"}, prefix, RoleAdmin},
		{"admin group with extra unrelated groups", []string{"vpn_users", "modulab_admin", "wifi"}, prefix, RoleAdmin},
		{"wrong prefix does not match", []string{"admin"}, prefix, RolePending},
		{"different configured prefix", []string{"acme-admin"}, "acme-", RoleAdmin},
		{"case-sensitive: does not match differently-cased group", []string{"Modulab_Admin"}, prefix, RolePending},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveRole(tc.groups, tc.prefix)
			if got != tc.want {
				t.Fatalf("DeriveRole(%v, %q) = %q, want %q", tc.groups, tc.prefix, got, tc.want)
			}
		})
	}
}
