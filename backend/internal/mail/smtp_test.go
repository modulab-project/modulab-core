package mail

import "testing"

// stripCRLF is the SMTP header-injection guard applied to any attacker-
// influenced value (e.g. a user's display name) before it is embedded in a
// mail header - without it, an embedded CRLF could inject extra headers or
// start a new message body.
func TestStripCRLF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text unchanged", "Jane Doe", "Jane Doe"},
		{"empty string", "", ""},
		{"strips bare LF", "Jane\nDoe", "JaneDoe"},
		{"strips bare CR", "Jane\rDoe", "JaneDoe"},
		{"strips CRLF pair", "Jane\r\nDoe", "JaneDoe"},
		{"strips header injection attempt", "Jane\r\nBcc: attacker@evil.example", "JaneBcc: attacker@evil.example"},
		{"strips multiple occurrences", "a\r\nb\r\nc\nd\re", "abcde"},
		{"unicode is preserved", "Jane Müller\r\n", "Jane Müller"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripCRLF(tc.in)
			if got != tc.want {
				t.Fatalf("stripCRLF(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
