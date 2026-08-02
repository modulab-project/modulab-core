// Egress policy: the bound within which a module may grant itself network
// access at runtime.
//
// Background (2026-07-27 security audit). A Tier 2/3 worker's --allow-net
// flag is built from manifest.yaml's egress_allowlist - the contract an admin
// reads before installing, and the reason WorkerOptions' doc comment can
// claim each worker gets "exactly the access its manifest declares, never
// more". Two runtime channels existed alongside it, both added for a real
// need (unifi-network's gateway IPs are entered by the admin long after
// install, so its manifest declares egress_allowlist: [] by design):
//
//   - WorkerResponse.RestartHosts, which any handler or job response may
//     carry (router.go / jobs.go), and
//   - EgressHostsHandler, which Core dispatches to ask the module itself
//     what it needs (WorkerPool.QueryEgressHosts).
//
// Both fed straight into ReloadEgress -> Start -> buildWorker -> --allow-net with no
// check of any kind. A module could therefore answer any request with
// {"restartHosts": ["attacker.example", "169.254.169.254", "10.0.0.5"]} and
// restart itself seconds later holding exactly that grant - the manifest the
// admin reviewed became advisory. That is not privilege escalation into Core
// (the worker's --allow-read/--allow-write/--allow-env scopes are untouched,
// and its env holds nothing borrowed from Core), but it does defeat the
// containment half of the sandbox: whatever a module can read - including
// the PII it decrypts with the shared MODULAB_MODULE_PII_KEY - it could ship
// anywhere, and it could reach the internal network that netguard carefully
// keeps Core itself out of.
//
// The fix keeps both channels working and constrains them instead: a module
// that wants runtime egress declares the *bound* in its manifest
// (dynamic_egress_allow), and Core intersects whatever the module asks for
// against it. unifi-network still learns its gateways at runtime and needs
// no manifest change when an admin adds one - it just has to say up front
// "my destinations live in the LAN".
//
// Note what this deliberately does NOT do: it does not force modules to be
// narrow. A module whose destinations genuinely cannot be predicted may
// declare "*" and keep exactly today's freedom. What changes is that the
// capability is now written down where an admin sees it before installing,
// instead of being invisible. Disclosure, not restriction, is the property
// being restored here - which is also why "*" is a legal pattern rather than
// something this file refuses to parse.
package modules

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// egressPolicyWildcard is the "any host at all" pattern. Spelled out as a
// constant so the (deliberate, see the package comment) decision to support
// it is greppable rather than looking like a missing case.
const egressPolicyWildcard = "*"

// normalizeEgressHost reduces an egress entry to the bare host it names, so
// a policy can be matched against it regardless of which shape the module
// reported.
//
// Modules are documented to report bare hostnames, but in practice a handler
// often has a base URL at hand ("https://192.168.1.1:8443/") and passes that
// - unifi-network's gateways are stored as URLs, not hosts. Rather than have
// the policy check silently fail closed on a shape that ReloadEgress would
// happily have granted before, strip scheme, userinfo, port, and path here
// and match on what is left. The original string is what gets granted; this
// normalization only ever feeds the comparison.
func normalizeEgressHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if i := strings.Index(h, "://"); i != -1 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i != -1 {
		h = h[:i]
	}
	// Userinfo last-wins: "user@host" -> "host". LastIndex rather than Index
	// so a password containing "@" cannot smuggle a different host past this.
	if i := strings.LastIndex(h, "@"); i != -1 {
		h = h[i+1:]
	}
	// SplitHostPort only succeeds when a port is actually present, and knows
	// about the [::1]:53 bracket form; the error case means "no port", which
	// is the common one, so h is left as-is.
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return strings.ToLower(h)
}

// validateEgressPolicyPattern rejects a dynamic_egress_allow entry that could
// never mean what its author intended. Called at install/update time
// (validateManifestTier) rather than only when a host is checked against it:
// a typo'd CIDR that silently matches nothing would otherwise surface as
// "the module mysteriously has no network" weeks later, which is exactly the
// failure mode the DynamicEgress work was originally chasing.
//
// Accepted shapes:
//
//	"*"                 any host (see the package comment)
//	"192.168.0.0/16"    CIDR, matched against reported IP literals
//	"*.example.com"     any subdomain of example.com (not example.com itself)
//	"example.com"       exactly that host
//	"10.0.0.5"          exactly that IP
func validateEgressPolicyPattern(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("empty pattern")
	}
	if p == egressPolicyWildcard {
		return nil
	}
	if strings.Contains(p, "/") {
		if _, _, err := net.ParseCIDR(p); err != nil {
			return fmt.Errorf("%q is not a valid CIDR: %w", p, err)
		}
		return nil
	}
	if strings.HasPrefix(p, "*.") {
		rest := p[2:]
		if rest == "" || strings.Contains(rest, "*") {
			return fmt.Errorf("%q: a wildcard host must look like \"*.example.com\"", p)
		}
		return nil
	}
	if strings.Contains(p, "*") {
		return fmt.Errorf("%q: \"*\" is only allowed on its own or as a leading \"*.\" label", p)
	}
	return nil
}

// matchesEgressPolicy reports whether host falls within any of patterns.
//
// A CIDR pattern only ever matches an IP literal: Core deliberately does not
// resolve a reported hostname to decide this. Resolving here would make the
// grant depend on a DNS answer at exactly the moment an attacker-controlled
// name could point anywhere (and would then be re-resolved by Deno at connect
// time anyway, so the check would guard nothing). A module whose policy is
// expressed as a CIDR must therefore report IPs - which is the natural shape
// for the case CIDRs exist for, an admin-entered LAN address.
func matchesEgressPolicy(host string, patterns []string) bool {
	h := normalizeEgressHost(host)
	if h == "" {
		return false
	}
	ip := net.ParseIP(h)

	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case p == "":
			continue
		case p == egressPolicyWildcard:
			return true
		case strings.Contains(p, "/"):
			_, network, err := net.ParseCIDR(p)
			if err != nil || ip == nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		case strings.HasPrefix(p, "*."):
			// "*.example.com" -> suffix ".example.com". The length check
			// keeps the bare parent domain out: a policy for subdomains
			// should not silently cover example.com itself, and an author
			// who wants both can list both.
			suffix := p[1:]
			if len(h) > len(suffix) && strings.HasSuffix(h, suffix) {
				return true
			}
		default:
			if h == normalizeEgressHost(p) {
				return true
			}
		}
	}
	return false
}

// filterEgressHosts splits hosts into the ones patterns permits and the ones
// it does not.
//
// Rejected hosts are returned rather than turned into an error so the caller
// can apply the allowed remainder and still surface the refusal loudly. The
// alternative - failing the whole reload - would mean one bad entry silently
// costs a module every other destination it legitimately had, turning a
// policy violation into an outage. Callers must not drop the rejected list on
// the floor: an empty patterns list makes this reject everything, which is
// the intended fail-closed behaviour for a module that asks for runtime
// egress without declaring a bound, and needs to be visible when it happens.
func filterEgressHosts(hosts, patterns []string) (allowed, rejected []string) {
	for _, h := range hosts {
		if matchesEgressPolicy(h, patterns) {
			allowed = append(allowed, h)
		} else {
			rejected = append(rejected, h)
		}
	}
	return allowed, rejected
}

// carryOverRuntimeEgress re-checks runtime egress hosts that survived a
// worker restart (WorkerPool.CurrentModuleEgressHosts) against the policy of
// the manifest now being started, dropping any the new policy no longer
// covers.
//
// Used by the module update and restart paths in handlers.go, which build
// WorkerOptions directly rather than going through ReloadEgress, so they do
// not otherwise pass through that function's check. Without this, tightening
// dynamic_egress_allow in a module update would leave the previously granted
// hosts in place until something happened to trigger a reload - i.e. the one
// moment an operator is most likely to be deliberately narrowing a module's
// reach would be the moment the narrowing did not apply.
//
// Logs rather than reporting through onEgressDeny: these hosts were legal
// when they were granted, so a rejection here is the expected consequence of
// an operator editing the manifest, not a module reaching past its bound.
func carryOverRuntimeEgress(moduleName string, hosts, patterns []string, action string) []string {
	allowed, rejected := filterEgressHosts(hosts, patterns)
	if len(rejected) > 0 {
		log.Printf("modules: %s %q: dropping carried-over egress hosts %v (outside dynamic_egress_allow=%v)",
			action, moduleName, rejected, patterns)
	}
	return allowed
}
