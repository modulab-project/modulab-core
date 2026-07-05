// Package netguard provides an http.Client whose Transport refuses to
// connect to loopback, link-local, private (RFC1918/RFC4193), or CGNAT
// addresses. Use it for any outbound request whose target host comes from
// admin-configured input (news feed URLs, AI provider base_url, SearXNG
// base_url) - without this, an admin account (or a compromised admin
// session) could point Core at an internal service, a cloud metadata
// endpoint (169.254.169.254), or anything else reachable from the host
// network, and read the response back through whatever feature made the
// request.
//
// The check runs inside Transport.DialContext, against the IP actually
// being connected to - not against the hostname at URL-parse time. That
// matters because a hostname can resolve to a different IP between when a
// URL is validated and when it's actually fetched (DNS rebinding): first
// resolve to a public IP to pass an earlier check, then to 127.0.0.1 by
// the time the real request goes out. Enforcing the check at dial time,
// and dialing the exact IP that was just validated (rather than letting
// the dialer re-resolve the hostname a second time), closes that gap.
//
// Added 2026-07-05 after a pre-V1 security review flagged SSRF risk in
// news.fetchFeed, ai.fetchModels/streamOpenAICompat, and
// searxng.Ping/fetchPage - all three previously validated only that a URL
// was syntactically http(s), never the IP it actually resolved to.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// cgnatBlock is the shared/carrier-grade NAT range (RFC 6598) - not
// covered by net.IP.IsPrivate, which only knows RFC 1918 + RFC 4193.
var cgnatBlock = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("netguard: invalid CIDR %q: %v", s, err))
	}
	return n
}

// isPublicIP reports whether ip is safe to let an admin-configured feature
// connect to - i.e. not loopback, link-local, private, unspecified, or
// CGNAT.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	if cgnatBlock.Contains(ip) {
		return false
	}
	return true
}

// SafeHTTPClient returns an *http.Client configured with the dial-time IP
// guard described in this package's doc comment. timeout applies to the
// whole request (http.Client.Timeout), separate from the shorter per-dial
// timeout used for the TCP connect itself.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("netguard: split host/port %q: %w", addr, err)
			}
			ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("netguard: resolve %q: %w", host, err)
			}
			if len(ipAddrs) == 0 {
				return nil, fmt.Errorf("netguard: %q resolved to no addresses", host)
			}
			for _, ipAddr := range ipAddrs {
				if !isPublicIP(ipAddr.IP) {
					return nil, fmt.Errorf("netguard: refusing to connect to non-public address %s (resolved from %q)", ipAddr.IP, host)
				}
			}
			// Dial the exact IP just validated, rather than handing addr
			// (the hostname) to dialer.DialContext and letting it resolve
			// a second time - a second resolution could return a
			// different, unvalidated IP (the DNS-rebinding scenario this
			// package exists to close).
			return dialer.DialContext(ctx, network, net.JoinHostPort(ipAddrs[0].IP.String(), port))
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
