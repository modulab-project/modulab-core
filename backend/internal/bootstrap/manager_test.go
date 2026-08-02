package bootstrap

import (
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return m
}

// blockedFor is the read side of the bootstrap-token brute-force guard: an
// address with no recorded failures is never blocked, one still under
// exponential backoff is blocked until nextAllowed, and one that tripped the
// hard per-address block is blocked until blockedUntil regardless of
// nextAllowed.
func TestManager_BlockedFor(t *testing.T) {
	m := newTestManager(t)

	if d := m.blockedFor("1.2.3.4"); d != 0 {
		t.Fatalf("unknown address should never be blocked, got %v", d)
	}

	m.attempts["1.2.3.4"] = &attemptState{nextAllowed: time.Now().Add(5 * time.Second)}
	if d := m.blockedFor("1.2.3.4"); d <= 0 {
		t.Fatalf("address with future nextAllowed should be blocked, got %v", d)
	}

	m.attempts["5.6.7.8"] = &attemptState{nextAllowed: time.Now().Add(-5 * time.Second)}
	if d := m.blockedFor("5.6.7.8"); d != 0 {
		t.Fatalf("address with past nextAllowed should not be blocked, got %v", d)
	}

	m.attempts["9.9.9.9"] = &attemptState{blockedUntil: time.Now().Add(time.Hour)}
	if d := m.blockedFor("9.9.9.9"); d <= 0 {
		t.Fatalf("address with future blockedUntil should be blocked, got %v", d)
	}
}

// recordFailure is the write side: exponential backoff per address (1s, 2s,
// 4s, 8s, ...), a hard per-address block after failuresBeforeIPBlock
// failures, and a process-wide pause after failuresBeforeGlobalPause total
// failures across any addresses.
func TestManager_RecordFailure_ExponentialBackoff(t *testing.T) {
	m := newTestManager(t)

	const addr = "1.2.3.4"
	prevNextAllowed := time.Now()
	for i := 1; i <= 3; i++ {
		_, blocked := m.recordFailure(addr)
		if blocked {
			t.Fatalf("failure %d: should not yet be IP-blocked (threshold is %d)", i, failuresBeforeIPBlock)
		}
		st := m.attempts[addr]
		if st.failures != i {
			t.Fatalf("failure %d: st.failures = %d, want %d", i, st.failures, i)
		}
		if !st.nextAllowed.After(prevNextAllowed) {
			t.Fatalf("failure %d: nextAllowed did not increase", i)
		}
		prevNextAllowed = st.nextAllowed
	}
}

func TestManager_RecordFailure_IPBlockAfterThreshold(t *testing.T) {
	m := newTestManager(t)
	const addr = "1.2.3.4"

	var blocked bool
	for i := 0; i < failuresBeforeIPBlock; i++ {
		_, blocked = m.recordFailure(addr)
	}
	if !blocked {
		t.Fatalf("expected blocked=true after %d failures from the same address", failuresBeforeIPBlock)
	}
	if d := m.blockedFor(addr); d <= 0 {
		t.Fatalf("blockedFor should report a positive block duration after IP block, got %v", d)
	}
}

func TestManager_RecordFailure_GlobalPauseAfterThreshold(t *testing.T) {
	m := newTestManager(t)

	// Spread failures across many distinct addresses so no single address
	// crosses failuresBeforeIPBlock - only the global counter should trip.
	for i := 0; i < failuresBeforeGlobalPause; i++ {
		addr := string(rune('a' + i))
		m.recordFailure(addr)
	}

	m.mu.Lock()
	paused := m.paused
	globalFailures := m.globalFailures
	m.mu.Unlock()

	if !paused {
		t.Fatalf("expected m.paused = true after %d total failures across distinct addresses, globalFailures=%d", failuresBeforeGlobalPause, globalFailures)
	}
}

// isTrustedProxyPeer (duplicated in internal/auth and cmd/core - see those
// packages' own tests) governs whether X-Forwarded-For is trusted for
// bucketing recordFailure/blockedFor by client IP instead of the immediate
// TCP peer.
func TestIsTrustedProxyPeer(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		{"loopback", "127.0.0.1", true},
		{"private", "10.0.0.5", true},
		{"public", "8.8.8.8", false},
		{"not an IP", "nginx", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTrustedProxyPeer(tc.host); got != tc.want {
				t.Fatalf("isTrustedProxyPeer(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
