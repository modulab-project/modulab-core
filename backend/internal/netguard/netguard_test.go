package netguard

import (
	"net"
	"testing"
)

// isPublicIP is the core SSRF defense behind SafeHTTPClient's dial guard -
// every address a resolved hostname produces is checked against this before
// Core is allowed to connect to it.
func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"public IPv4", "8.8.8.8", true},
		{"public IPv6", "2001:4860:4860::8888", true},
		{"loopback v4 rejected", "127.0.0.1", false},
		{"loopback v6 rejected", "::1", false},
		{"link-local unicast rejected", "169.254.1.1", false},
		{"link-local multicast rejected", "224.0.0.251", false},
		{"unspecified v4 rejected", "0.0.0.0", false},
		{"unspecified v6 rejected", "::", false},
		{"private 10.x rejected", "10.0.0.1", false},
		{"private 172.16.x rejected", "172.20.5.5", false},
		{"private 192.168.x rejected", "192.168.1.1", false},
		{"CGNAT range rejected", "100.64.0.1", false},
		{"CGNAT range upper bound rejected", "100.127.255.254", false},
		{"just outside CGNAT range is public", "100.63.255.255", true},
		{"just outside CGNAT range upper is public", "100.128.0.0", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test setup: %q is not a valid IP", tc.ip)
			}
			got := isPublicIP(ip)
			if got != tc.want {
				t.Fatalf("isPublicIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}
