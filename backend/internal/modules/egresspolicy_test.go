package modules

import "testing"

// validateEgressPolicyPattern is what stands between a manifest's
// dynamic_egress_allow entries and a silently-matches-nothing typo (Audit
// 2026-08-02, A-1 #5).
func TestValidateEgressPolicyPattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"wildcard is allowed", "*", false},
		{"exact host", "example.com", false},
		{"exact IP", "10.0.0.5", false},
		{"valid CIDR", "192.168.0.0/16", false},
		{"invalid CIDR", "192.168.0.0/99", true},
		{"invalid CIDR garbage", "not-a-cidr/16", true},
		{"subdomain wildcard", "*.example.com", false},
		{"subdomain wildcard with empty parent", "*.", true},
		{"subdomain wildcard with nested wildcard", "*.*.example.com", true},
		{"wildcard not on its own or leading", "ex*ample.com", true},
		{"empty pattern", "", true},
		{"whitespace-only pattern", "   ", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEgressPolicyPattern(tc.pattern)
			if tc.wantErr && err == nil {
				t.Fatalf("pattern %q: expected error, got nil", tc.pattern)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("pattern %q: expected no error, got: %v", tc.pattern, err)
			}
		})
	}
}

// matchesEgressPolicy is the fail-closed gate applied to both
// WorkerResponse.RestartHosts and EgressHostsHandler's answer before either
// ever reaches --allow-net (Audit 2026-08-02, A-1 #5) - this is the actual
// security boundary; validateEgressPolicyPattern above only catches bad
// patterns at install time.
func TestMatchesEgressPolicy(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		patterns []string
		want     bool
	}{
		{"empty patterns rejects everything (fail closed)", "example.com", nil, false},
		{"wildcard matches anything", "attacker.example", []string{"*"}, true},
		{"exact host match", "example.com", []string{"example.com"}, true},
		{"exact host is case-insensitive", "EXAMPLE.com", []string{"example.com"}, true},
		{"exact host mismatch", "evil.example", []string{"example.com"}, false},
		{"CIDR matches contained IP", "192.168.1.42", []string{"192.168.0.0/16"}, true},
		{"CIDR rejects IP outside range", "10.0.0.5", []string{"192.168.0.0/16"}, false},
		{"CIDR pattern does not match a hostname", "example.com", []string{"192.168.0.0/16"}, false},
		{"subdomain wildcard matches subdomain", "api.example.com", []string{"*.example.com"}, true},
		{"subdomain wildcard does not match bare parent domain", "example.com", []string{"*.example.com"}, false},
		{"subdomain wildcard does not match unrelated suffix collision", "notexample.com", []string{"*.example.com"}, false},
		{"host reported as a URL is normalized before matching", "https://192.168.1.1:8443/status", []string{"192.168.1.1"}, true},
		{"host with userinfo is normalized", "admin@192.168.1.1", []string{"192.168.1.1"}, true},
		{"empty host never matches", "", []string{"*"}, false},
		{"one of several patterns matches", "example.com", []string{"other.com", "example.com"}, true},
		{"none of several patterns matches", "example.com", []string{"other.com", "third.com"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesEgressPolicy(tc.host, tc.patterns)
			if got != tc.want {
				t.Fatalf("matchesEgressPolicy(%q, %v) = %v, want %v", tc.host, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestFilterEgressHosts(t *testing.T) {
	hosts := []string{"good.example.com", "evil.attacker.example", "192.168.1.1"}
	patterns := []string{"*.example.com", "192.168.1.1"}

	allowed, rejected := filterEgressHosts(hosts, patterns)

	if len(allowed) != 2 || allowed[0] != "good.example.com" || allowed[1] != "192.168.1.1" {
		t.Fatalf("allowed = %v, want [good.example.com 192.168.1.1]", allowed)
	}
	if len(rejected) != 1 || rejected[0] != "evil.attacker.example" {
		t.Fatalf("rejected = %v, want [evil.attacker.example]", rejected)
	}
}

func TestFilterEgressHosts_EmptyPatternsRejectsAll(t *testing.T) {
	allowed, rejected := filterEgressHosts([]string{"a.com", "b.com"}, nil)
	if len(allowed) != 0 {
		t.Fatalf("allowed = %v, want empty (fail closed with no patterns)", allowed)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %v, want both hosts rejected", rejected)
	}
}

func TestNormalizeEgressHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.com", "example.com"},
		{"https://example.com/path?query#frag", "example.com"},
		{"example.com:8443", "example.com"},
		{"admin@example.com", "example.com"},
		{"user:pass@example.com:8443", "example.com"},
		{"[::1]:53", "::1"},
		{"  example.com  ", "example.com"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := normalizeEgressHost(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeEgressHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
