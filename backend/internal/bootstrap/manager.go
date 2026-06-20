// Package bootstrap implements the Setup Wizard's bootstrap-token gate
// (spec section 6.5): until the wizard has been completed, every request to
// the Setup Wizard's API must present a one-time token that ModuLab Core
// generates at startup and prints to its own log exactly once. The token
// lives only in process memory - it is never written to the database - so
// a restart before the wizard finishes always produces a fresh one.
package bootstrap

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HeaderName is the request header clients must set to the bootstrap token.
const HeaderName = "X-ModuLab-Bootstrap-Token"

const (
	failuresBeforeIPBlock    = 5
	ipBlockDuration          = time.Hour
	failuresBeforeGlobalPause = 10
)

// Manager guards the Setup Wizard's API surface with the bootstrap token.
// It also implements the rate-limiting behaviour spec section 6.5
// describes: exponential backoff per client address, a 1-hour block after 5
// failures from the same address, and a process-wide pause (requiring a
// manual restart) after 10 total failures, since that pattern looks like a
// distributed attempt rather than one confused operator.
type Manager struct {
	mu sync.Mutex

	token     string
	completed bool
	paused    bool

	globalFailures int
	attempts       map[string]*attemptState
}

type attemptState struct {
	failures     int
	nextAllowed  time.Time
	blockedUntil time.Time
}

// New generates a fresh bootstrap token and logs it exactly once, in the
// format spec section 6.5 shows operators to look for. Call it once at
// startup, before wiring up the Setup Wizard's routes.
//
// Marking the wizard as completed (which permanently disables this gate) is
// not implemented yet - it depends on the super-admin OIDC binding step
// (spec section 6.5 step 6), which has not landed. Until then, Manager
// always starts in the "not completed" state on every restart, which is the
// correct behaviour for an instance that has never finished setup.
func New() (*Manager, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: generate token: %w", err)
	}
	m := &Manager{
		token:    token,
		attempts: make(map[string]*attemptState),
	}
	logToken(token)
	return m, nil
}

// Middleware wraps next so that every request must present the correct
// bootstrap token via the HeaderName header, unless the wizard has already
// been completed.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		completed := m.completed
		paused := m.paused
		m.mu.Unlock()

		if completed {
			next.ServeHTTP(w, r)
			return
		}
		if paused {
			http.Error(w, "setup endpoint paused after repeated failed bootstrap-token attempts; restart modulab-core to resume", http.StatusServiceUnavailable)
			return
		}

		ip := clientIP(r)

		if wait := m.blockedFor(ip); wait > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
			http.Error(w, "too many failed bootstrap-token attempts from this address, temporarily blocked", http.StatusTooManyRequests)
			return
		}

		supplied := r.Header.Get(HeaderName)
		if supplied != "" && m.validate(supplied) {
			m.recordSuccess(ip)
			next.ServeHTTP(w, r)
			return
		}

		retryAfter, blocked := m.recordFailure(ip)
		if blocked {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(ipBlockDuration.Seconds())))
			http.Error(w, "too many failed bootstrap-token attempts from this address, blocked for 1 hour", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		http.Error(w, fmt.Sprintf("missing or invalid %s header", HeaderName), http.StatusUnauthorized)
	})
}

func (m *Manager) validate(supplied string) bool {
	m.mu.Lock()
	token := m.token
	m.mu.Unlock()
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) == 1
}

func (m *Manager) blockedFor(ip string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.attempts[ip]
	if st == nil {
		return 0
	}
	now := time.Now()
	if now.Before(st.blockedUntil) {
		return st.blockedUntil.Sub(now)
	}
	if now.Before(st.nextAllowed) {
		return st.nextAllowed.Sub(now)
	}
	return 0
}

func (m *Manager) recordFailure(ip string) (retryAfter time.Duration, blocked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.attempts[ip]
	if st == nil {
		st = &attemptState{}
		m.attempts[ip] = st
	}
	st.failures++
	m.globalFailures++

	backoff := time.Duration(1<<uint(st.failures-1)) * time.Second // 1s, 2s, 4s, 8s, ...
	st.nextAllowed = time.Now().Add(backoff)

	if st.failures >= failuresBeforeIPBlock {
		st.blockedUntil = time.Now().Add(ipBlockDuration)
		log.Printf("bootstrap: ALERT - address %s blocked for %s after %d failed bootstrap-token attempts", ip, ipBlockDuration, st.failures)
		blocked = true
	}

	if m.globalFailures >= failuresBeforeGlobalPause && !m.paused {
		m.paused = true
		log.Printf("bootstrap: ALERT - setup endpoint paused after %d total failed bootstrap-token attempts across one or more addresses; restart modulab-core to resume", m.globalFailures)
	}

	return backoff, blocked
}

func (m *Manager) recordSuccess(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.attempts, ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateToken() (string, error) {
	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "mlab_" + base58Encode(buf), nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode implements the Bitcoin-style Base58 alphabet spec section
// 6.5 specifies for the bootstrap token. The stdlib has no Base58 encoder,
// and pulling in a dependency for ~20 lines of big-integer division did not
// seem worth it.
func base58Encode(input []byte) string {
	num := new(big.Int).SetBytes(input)
	zero := big.NewInt(0)
	base := big.NewInt(58)
	mod := new(big.Int)

	var encoded []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	leadingZeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}
	return strings.Repeat("1", leadingZeros) + string(encoded)
}

func logToken(token string) {
	log.Print("\n" + strings.Join([]string{
		"╔══════════════════════════════════════════════════════════════╗",
		"║              MODULAB CORE — FIRST-TIME SETUP REQUIRED         ║",
		"║                                                                ║",
		"║  Bootstrap Token:                                             ║",
		"║  " + token,
		"║                                                                ║",
		"║  This token is shown ONLY ONCE.                               ║",
		"║  Setup cannot be completed without it.                       ║",
		"╚══════════════════════════════════════════════════════════════╝",
	}, "\n") + "\n")
}
