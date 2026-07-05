// Package tlscheck reads the expiry of the TLS certificate a reverse proxy
// (Traefik in modulab-core's shipped deploy/docker-compose.yml) is currently
// serving, for the System Info page's "certificate expires in N days" row.
//
// It deliberately does not read Traefik's acme.json directly: that file
// lives in a Docker volume only the traefik container mounts, and it holds
// the private key alongside the certificate - sharing that volume with Core
// just to read an expiry date would mean handing Core access to a secret it
// has no other reason to see, and parsing Traefik's internal storage format
// ties this check to Traefik specifically. Dialing the TLS port and reading
// the handshake's own certificate instead is the same technique any external
// uptime/cert monitor uses (openssl s_client, sslmate, etc.) - it works
// regardless of what's actually terminating TLS on the other end.
package tlscheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// dialTimeout caps the whole check (TCP connect + TLS handshake) so a
// firewalled or unreachable addr fails fast rather than blocking the System
// Info page's response.
const dialTimeout = 3 * time.Second

// Expiry dials addr ("host:port", typically the reverse proxy's HTTPS
// entrypoint on the internal Docker network - see config.TLSCheckAddr) and
// returns the NotAfter timestamp of the certificate served for serverName.
//
// InsecureSkipVerify is intentional, not an oversight: addr is a Docker
// service name (e.g. "traefik:443"), not the certificate's actual public
// hostname, so full chain+hostname verification would always fail here even
// against a perfectly valid certificate. serverName is still sent via SNI so
// a proxy hosting multiple vhosts (Traefik does, per-router) returns the
// right certificate - this function only reads metadata from what comes
// back, it never uses the connection to transmit or trust anything.
func Expiry(ctx context.Context, addr, serverName string) (time.Time, error) {
	if addr == "" {
		return time.Time{}, fmt.Errorf("tlscheck: no address configured")
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return time.Time{}, fmt.Errorf("tlscheck: dial %q: %w", addr, err)
	}
	defer rawConn.Close()

	// Deadline on the handshake itself too - DialContext above only bounds
	// the TCP connect, not the TLS handshake that follows.
	if err := rawConn.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		return time.Time{}, fmt.Errorf("tlscheck: set deadline: %w", err)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return time.Time{}, fmt.Errorf("tlscheck: handshake with %q: %w", addr, err)
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("tlscheck: %q presented no certificate", addr)
	}
	// certs[0] is always the leaf (the server's own certificate, not an
	// intermediate/root CA) - that is what expires and needs renewing.
	return certs[0].NotAfter, nil
}
