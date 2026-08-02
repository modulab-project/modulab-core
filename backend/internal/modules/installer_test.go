package modules

import (
	"strings"
	"testing"
)

// Table-driven cases for validateManifestTier - see the function's own doc
// comment in installer.go for the full rule set (Audit 2026-08-02, A-1 #1).
func TestValidateManifestTier(t *testing.T) {
	validCrud := &ManifestCrud{
		Table:  "items",
		Fields: []ManifestCrudField{{Name: "title", Type: "string"}},
	}

	cases := []struct {
		name    string
		mf      Manifest
		wantErr bool
		errSub  string // substring expected in the error, "" = don't check
	}{
		{
			name: "valid tier 1 with crud",
			mf:   Manifest{Name: "pantry", Tier: 1, Crud: validCrud},
		},
		{
			name: "valid tier 2 with handler",
			mf:   Manifest{Name: "recipes", Tier: 2, Handler: "handler.ts"},
		},
		{
			name: "valid tier 3 with handler and egress",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts",
				EgressAllowlist: []string{"192.168.1.1"},
			},
		},
		{
			name:    "invalid name uppercase",
			mf:      Manifest{Name: "MyPlace", Tier: 1, Crud: validCrud},
			wantErr: true,
			errSub:  "invalid module name",
		},
		{
			name:    "invalid name path traversal",
			mf:      Manifest{Name: "../../etc", Tier: 1, Crud: validCrud},
			wantErr: true,
			errSub:  "invalid module name",
		},
		{
			name:    "handler escapes module dir",
			mf:      Manifest{Name: "recipes", Tier: 2, Handler: "../../evil.ts"},
			wantErr: true,
			errSub:  "escapes the module directory",
		},
		{
			name:    "handler absolute path",
			mf:      Manifest{Name: "recipes", Tier: 2, Handler: "/etc/passwd"},
			wantErr: true,
			errSub:  "must be a relative path",
		},
		{
			name: "job handler escapes module dir",
			mf: Manifest{
				Name: "recipes", Tier: 2, Handler: "handler.ts",
				Jobs: []ManifestJob{{Name: "sync", Schedule: "* * * * *", Handler: "../../job.ts"}},
			},
			wantErr: true,
			errSub:  "escapes the module directory",
		},
		{
			name:    "tier out of range low",
			mf:      Manifest{Name: "pantry", Tier: 0, Crud: validCrud},
			wantErr: true,
			errSub:  "invalid tier",
		},
		{
			name:    "tier out of range high",
			mf:      Manifest{Name: "pantry", Tier: 4, Crud: validCrud},
			wantErr: true,
			errSub:  "invalid tier",
		},
		{
			name:    "tier 1 must not declare handler",
			mf:      Manifest{Name: "pantry", Tier: 1, Handler: "handler.ts", Crud: validCrud},
			wantErr: true,
			errSub:  "must not declare handler",
		},
		{
			name: "tier 1 must not declare jobs",
			mf: Manifest{
				Name: "pantry", Tier: 1, Crud: validCrud,
				Jobs: []ManifestJob{{Name: "sync", Schedule: "* * * * *", Handler: "job.ts"}},
			},
			wantErr: true,
			errSub:  "must not declare handler/jobs/egress_allowlist",
		},
		{
			name:    "tier 1 must not declare egress_allowlist",
			mf:      Manifest{Name: "pantry", Tier: 1, Crud: validCrud, EgressAllowlist: []string{"example.com"}},
			wantErr: true,
			errSub:  "must not declare handler/jobs/egress_allowlist",
		},
		{
			name:    "tier 1 requires crud block",
			mf:      Manifest{Name: "pantry", Tier: 1},
			wantErr: true,
			errSub:  "requires a crud block",
		},
		{
			name:    "tier 1 requires at least one field",
			mf:      Manifest{Name: "pantry", Tier: 1, Crud: &ManifestCrud{Table: "items"}},
			wantErr: true,
			errSub:  "requires a crud block",
		},
		{
			name:    "tier 2 must not declare crud",
			mf:      Manifest{Name: "recipes", Tier: 2, Handler: "handler.ts", Crud: validCrud},
			wantErr: true,
			errSub:  "must not declare crud",
		},
		{
			name:    "tier 2 requires a handler",
			mf:      Manifest{Name: "recipes", Tier: 2},
			wantErr: true,
			errSub:  "requires a handler",
		},
		{
			name:    "tier 2 must not declare egress_allowlist",
			mf:      Manifest{Name: "recipes", Tier: 2, Handler: "handler.ts", EgressAllowlist: []string{"example.com"}},
			wantErr: true,
			errSub:  "must not declare egress_allowlist",
		},
		{
			name: "tls_skip_verify without any egress source",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts", TLSSkipVerify: true,
			},
			wantErr: true,
			errSub:  "tls_skip_verify requires",
		},
		{
			name: "tls_skip_verify with static egress_allowlist is fine",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts", TLSSkipVerify: true,
				EgressAllowlist: []string{"192.168.1.1"},
			},
		},
		{
			name: "tls_skip_verify with dynamic_egress + handler is fine",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts", TLSSkipVerify: true,
				DynamicEgress: true, EgressHostsHandler: "egress.ts",
			},
		},
		{
			name: "tls_skip_verify with dynamic_egress but no handler still rejected",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts", TLSSkipVerify: true,
				DynamicEgress: true,
			},
			wantErr: true,
			errSub:  "tls_skip_verify requires",
		},
		{
			name: "invalid dynamic_egress_allow pattern",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts",
				DynamicEgress: true, DynamicEgressAllow: []string{"not a cidr/"},
			},
			wantErr: true,
			errSub:  "dynamic_egress_allow[0]",
		},
		{
			name: "dynamic_egress_allow without dynamic_egress is a contradiction",
			mf: Manifest{
				Name: "unifi-network", Tier: 3, Handler: "handler.ts",
				DynamicEgressAllow: []string{"*"},
			},
			wantErr: true,
			errSub:  "requires dynamic_egress: true",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateManifestTier(tc.mf)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if tc.wantErr && tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("expected error to contain %q, got: %v", tc.errSub, err)
			}
		})
	}
}

// validateSafeRelativePath is the path-traversal guard shared by handler /
// egress_hosts_handler / every job's handler (Audit 2026-08-02, A-1 #2).
func TestValidateSafeRelativePath(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty is allowed", "", false},
		{"simple relative path", "handler.ts", false},
		{"nested relative path", "src/handler.ts", false},
		{"absolute path rejected", "/etc/passwd", true},
		{"parent traversal rejected", "../../etc/cron.d/evil", true},
		{"bare dotdot rejected", "..", true},
		{"leading dotdot-slash rejected", "../evil.ts", true},
		{"windows backslash rejected", `..\..\evil.ts`, true},
		{"traversal buried in the middle is cleaned and still safe", "a/../b.ts", false},
		{"traversal that nets negative is rejected", "a/../../b.ts", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSafeRelativePath("handler", tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("path %q: expected error, got nil", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("path %q: expected no error, got: %v", tc.path, err)
			}
		})
	}
}

func TestValidateSafeRelativePath_FieldNameInError(t *testing.T) {
	err := validateSafeRelativePath("egress_hosts_handler", "/abs")
	if err == nil || !strings.Contains(err.Error(), "egress_hosts_handler") {
		t.Fatalf("expected error to name the field, got: %v", err)
	}
}
