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
// Manager always starts in the "not completed" state on every restart, even
// after a real install has finished the wizard once - see Complete's doc
// comment for why that is an acceptable trade-off rather than a bug.
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

// Complete permanently disables the bootstrap-token gate for the lifetime
// of this process (spec section 6.5 step 7: "Bootstrap-Token invalidiert,
// System geht in Normalbetrieb"). Called by setup.CompleteHandler once it
// has verified every prior wizard step (master key, OIDC, group prefix,
// DNS-challenge provider, and a bound Super-Admin) is actually persisted -
// Manager itself does not re-check those, it only flips the gate.
//
// This flag lives in memory only, exactly like the token itself: a restart
// after a real install has already completed the wizard once will print a
// fresh token and re-lock /v1/setup/* until CompleteHandler is called again.
// That is intentional rather than an oversight - every check CompleteHandler
// performs reads already-persisted state, so calling it again after a
// restart is a harmless no-op (idempotent), and re-locking the operator-only
// setup API on every restart is the conservative default until there is a
// concrete reason to persist completion to the database instead.
func (m *Manager) Complete() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completed = true
}

// Completed reports whether Complete has been called on this Manager
// instance yet.
func (m *Manager) Completed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.completed
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

// boxInnerWidth is the number of characters between the box's two vertical
// borders. boxLine/centeredBoxLine pad to this width at runtime rather than
// via hand-counted literal spaces, since the latter is exactly the kind of
// thing that silently drifts out of alignment whenever a line's text
// changes (as happened with the German-to-English wording switch).
const boxInnerWidth = 66

// boxLine pads text with trailing spaces so the line's right "║" lands at
// boxInnerWidth. If text is already too long to fit, it is returned with no
// padding or trailing border rather than corrupting the box - this is what
// happens to the bootstrap token line itself, since the token's length can
// vary slightly with its leading-zero-byte encoding.
func boxLine(text string) string {
	n := boxInnerWidth - len([]rune(text))
	if n < 0 {
		return "║" + text
	}
	return "║" + text + strings.Repeat(" ", n) + "║"
}

// centeredBoxLine is boxLine but centers text within boxInnerWidth instead
// of left-aligning it.
func centeredBoxLine(text string) string {
	n := boxInnerWidth - len([]rune(text))
	if n < 0 {
		return boxLine(text)
	}
	left := n / 2
	right := n - left
	return "║" + strings.Repeat(" ", left) + text + strings.Repeat(" ", right) + "║"
}

func logToken(token string) {
	top := "╔" + strings.Repeat("═", boxInnerWidth) + "╗"
	bottom := "╚" + strings.Repeat("═", boxInnerWidth) + "╝"

	log.Print("\n" + strings.Join([]string{
		top,
		centeredBoxLine("MODULAB CORE — FIRST-TIME SETUP REQUIRED"),
		boxLine(""),
		boxLine("  Bootstrap Token:"),
		boxLine("  " + token),
		boxLine(""),
		boxLine("  This token is shown ONLY ONCE."),
		boxLine("  Setup cannot be completed without it."),
		bottom,
	}, "\n") + "\n")
}
