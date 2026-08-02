package modules

import "testing"

// quoteIdent is the only thing standing between a manifest-supplied SQL
// identifier (module name -> schema name, crud.table, crud field names) and
// a raw string concatenation into a migration/CRUD statement - the most
// expensive possible mistake per the audit (2026-08-02, A-1 #2).
func TestQuoteIdent(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"simple identifier", "items", `"items"`},
		{"identifier with underscore", "module_pantry", `"module_pantry"`},
		// pgx.Identifier.Sanitize doubles embedded double quotes rather than
		// rejecting them - this is exactly what makes it safe to interpolate
		// straight into a query string afterwards.
		{"embedded double quote is escaped, not stripped", `evil"; DROP TABLE users; --`, `"evil""; DROP TABLE users; --"`},
		{"embedded single quote is left alone (harmless inside double quotes)", `o'brien`, `"o'brien"`},
		{"already-quoted-looking input is treated as one literal identifier", `"already"`, `"""already"""`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quoteIdent(tc.in)
			if got != tc.want {
				t.Fatalf("quoteIdent(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The property that actually matters for callers: whatever quoteIdent
// returns is always wrapped in exactly one pair of double quotes, so it can
// never be mistaken for anything other than a single quoted identifier by
// the SQL it gets concatenated into.
func TestQuoteIdent_AlwaysWrapped(t *testing.T) {
	inputs := []string{"items", `a"b`, "", "*", "a; DROP TABLE x", "SELECT"}
	for _, in := range inputs {
		got := quoteIdent(in)
		if len(got) < 2 || got[0] != '"' || got[len(got)-1] != '"' {
			t.Fatalf("quoteIdent(%q) = %q, not wrapped in a single pair of double quotes", in, got)
		}
	}
}
