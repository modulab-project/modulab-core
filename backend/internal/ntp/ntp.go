// Package ntp provides a lightweight system-clock sanity check using SNTPv4
// (RFC 4330). It sends a single UDP packet to pool.ntp.org:123 and compares
// the server's reported transmit timestamp against the local clock. A drift
// larger than the caller's threshold is returned as false, indicating that
// TLS certificate validation, OIDC JWT "iat"/"exp" checks, and the audit
// log's HMAC chain timestamps may be unreliable.
//
// The check is best-effort: if the UDP exchange times out (e.g. because
// pool.ntp.org is not reachable from this container) the caller receives an
// error and should surface the result as "unknown" rather than "bad".
package ntp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	// ntpEpochOffset is the number of seconds between 1 Jan 1900 (NTP epoch)
	// and 1 Jan 1970 (Unix epoch).
	ntpEpochOffset = 2208988800

	// server is the NTP pool used for the check. A single host rather than
	// pool.ntp.org's DNS round-robin to keep the implementation simple
	// (no retransmission, no source IP checks). Any of the pool's members
	// will do for a rough "is the clock wildly wrong" sanity check.
	server = "pool.ntp.org:123"

	// udpTimeout caps the total round-trip time for the SNTPv4 exchange.
	udpTimeout = 3 * time.Second
)

// DriftOK sends one SNTPv4 request to pool.ntp.org and reports whether the
// absolute difference between the server's transmit timestamp and the local
// clock is within maxDrift. Typical expected drift on a well-synced host is
// well under one second; 30 seconds is a generous threshold that still catches
// the "system clock is hours off" class of misconfiguration.
//
// Returns (false, nil) when drift exceeds maxDrift.
// Returns (false, err) when the check could not be completed (network
// unreachable, DNS failure, timeout).
func DriftOK(maxDrift time.Duration) (bool, error) {
	conn, err := net.DialTimeout("udp", server, udpTimeout)
	if err != nil {
		return false, fmt.Errorf("ntp: dial %s: %w", server, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("ntp: close udp conn: %v", err)
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(udpTimeout)); err != nil {
		return false, fmt.Errorf("ntp: set deadline: %w", err)
	}

	// 48-byte SNTPv4 request. Only byte 0 needs to be set:
	//   LI  = 00 (no leap second warning)
	//   VN  = 100 (version 4)
	//   Mode = 011 (client)
	// → 0b00_100_011 = 0x23.
	req := make([]byte, 48)
	req[0] = 0x23

	if _, err := conn.Write(req); err != nil {
		return false, fmt.Errorf("ntp: write request: %w", err)
	}

	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return false, fmt.Errorf("ntp: read response: %w", err)
	}

	// Transmit Timestamp (bytes 40–43: seconds, 44–47: fraction). We only
	// need second-level resolution for a clock sanity check, so the fraction
	// is ignored.
	serverSecs := binary.BigEndian.Uint32(resp[40:44])
	serverTime := time.Unix(int64(serverSecs)-ntpEpochOffset, 0)

	drift := time.Since(serverTime)
	if drift < 0 {
		drift = -drift
	}
	return drift <= maxDrift, nil
}
