// Package bootstrap implements the Setup Wizard's bootstrap-token gate
// (spec section 6.5): until the wizard has been completed, every request to
// the Setup Wizard's API must present a one-time token that ModuLab Core
// generates at startup. The token lives only in process memory - it is
// never written to the database - so a restart before the wizard finishes
// always produces a fresh one. Once the wizard HAS finished, main.go derives
// that fact from the database (via setup.WizardComplete) on every startup
// and calls Complete instead of LogToken, so a completed instance never
// prints a fresh token - and, from that point on, serves 404 for the entire
// wizard API rather than accepting any token for it. See LogToken,
// Middleware, and Complete's doc comments for the mechanics.
//
// The gate is therefore the only thing standing in front of the wizard
// handlers: none of them (setup.OIDCConfigureHandler,
// setup.GroupPrefixConfigureHandler, ...) performs an auth check of its own,
// by design - they run in a phase where no user account exists yet. Any
// change to Middleware's decision logic is a change to whether unauthenticated
// callers can rewrite this instance's OIDC trust root.
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
	failuresBeforeIPBlock     = 5
	ipBlockDuration           = time.Hour
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

// New generates a fresh bootstrap token. Call it once at startup, before
// wiring up the Setup Wizard's routes - it does not log or otherwise expose
// the token itself; the caller decides whether to via LogToken or Complete
// once it knows (from the database) whether a previous run already
// finished the wizard.
func New() (*Manager, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: generate token: %w", err)
	}
	m := &Manager{
		token:    token,
		attempts: make(map[string]*attemptState),
	}
	return m, nil
}

// LogToken prints the bootstrap token to the log in the boxed
// "FIRST-TIME SETUP REQUIRED" format spec section 6.5 shows operators to
// look for. Call this only when the wizard has not already been completed
// in a previous run - main.go checks setup.WizardComplete against the
// database before deciding between this and Complete, since printing a
// fresh token and claiming setup is still required would be actively
// misleading for an instance that already finished it.
func (m *Manager) LogToken() {
	m.mu.Lock()
	token := m.token
	m.mu.Unlock()
	logToken(token)
}

// Middleware wraps next so that every request must present the correct
// bootstrap token via the HeaderName header - and, once the wizard has been
// completed, so that next is never reached at all.
//
// The completed branch used to call next.ServeHTTP unconditionally, on the
// reading that "the gate exists only until setup is done". That was an
// authentication bypass, found in the 2026-07-27 security audit: none of
// the wizard handlers this middleware wraps has any auth check of its own
// (they were written for a phase where no user account can exist yet), and
// main.go calls Complete() at startup for every already-configured
// instance. So on any production deployment, POST /v1/setup/oidc/configure
// was reachable by anyone who could reach Core at all - and it overwrites
// issuer_url/client_id/client_secret, i.e. the trust root the entire login
// flow depends on. Whoever set those could point every subsequent login at
// an IdP of their own and log in as super-admin. POST
// /v1/setup/group-prefix/configure (rewrites role derivation) and GET
// /v1/setup/oidc/status (leaks issuer + client ID) were open the same way.
//
// A completed wizard has nothing left to serve: the SPA reads
// /healthz's setup_completed, not /v1/setup/status, and SetupWizard.tsx
// redirects /setup to /login outright once that flag is true - so no
// first-party caller loses anything here. 404 rather than 403 because
// "these routes do not exist on a configured instance" is the accurate
// description, and it does not confirm to a prober that a wizard API is
// merely gated. The ongoing, authenticated equivalents live in the admin
// panel (PATCH/DELETE /v1/admin/oidc, super-admin + step-up reauth) and are
// unaffected.
//
// Note this deliberately removes the "re-run the wizard to recover from a
// broken OIDC config" path, which was never a designed feature - only a
// side effect of the bypass. Recovery for a full lockout is an operator
// action against the database, not an unauthenticated HTTP endpoint.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		completed := m.completed
		paused := m.paused
		m.mu.Unlock()

		if completed {
			http.NotFound(w, r)
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

// Complete permanently closes the Setup Wizard API for the lifetime of this
// process (spec section 6.5 step 7: "Bootstrap-Token invalidiert, System
// geht in Normalbetrieb"). Called by setup.CompleteHandler once it has
// verified every prior wizard step (master key, OIDC, group prefix, and a
// bound Super-Admin) is actually persisted - Manager itself does not
// re-check those, it only flips the gate.
//
// "Closes", not "opens": after this flag is set, Middleware answers every
// wrapped route with 404 instead of forwarding it - see its doc comment for
// why forwarding was an authentication bypass. The bootstrap token stops
// being accepted at the same moment, so a completed instance has no path
// back into the wizard at all, with or without the token.
//
// Safe to call from a handler that this same Manager's Middleware is
// currently forwarding (setup.CompleteHandler does exactly that): the
// middleware already made its decision before invoking the handler, so
// flipping the flag mid-request only affects subsequent requests, never
// this one's own response.
//
// This flag lives in memory only and starts false on every process start,
// but main.go also calls Complete unconditionally at startup whenever
// setup.WizardComplete reports the database already has everything a
// finished wizard would have persisted - so a restart of an
// already-completed instance re-derives "completed" from real persisted
// state rather than losing it, without needing a redundant "completed" flag
// of its own in the database. Calling Complete twice (here and later via
// CompleteHandler, if the wizard somehow runs again) is harmless: it is
// just a flag flip.
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

// clientIP mirrors cmd/core/main.go's clientIP/isTrustedProxyPeer (kept in
// sync deliberately, duplicated rather than shared since bootstrap must not
// import the main package): honor X-Forwarded-For, but only when the
// immediate TCP peer is Traefik itself (loopback/private-range, since
// Traefik reaches Core over the Docker-internal network).
//
// Before this fix (2026-07-23 security pass) this used r.RemoteAddr alone.
// Behind Traefik that is always the proxy's own address, so every distinct
// external client's failed bootstrap-token attempts collapsed into one
// shared bucket - a single unauthenticated actor could trip both the
// per-address block (failuresBeforeIPBlock) and the process-wide
// failuresBeforeGlobalPause with a handful of requests, well before a real
// distributed attack would. Trusting XFF only from a private-range peer
// keeps that from being spoofable by an untrusted client while fixing the
// bucketing.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && isTrustedProxyPeer(host) {
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return host
}

// isTrustedProxyPeer reports whether host (the immediate TCP peer, before
// any X-Forwarded-For is considered) is a loopback or private-range
// address. See cmd/core/main.go's identical helper for the full reasoning.
func isTrustedProxyPeer(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
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
