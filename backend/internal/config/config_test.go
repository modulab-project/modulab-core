package config

import (
	"strings"
	"testing"
)

// validKeyHex is a syntactically valid 32-byte (64 hex char) key, used only
// in tests - never a real key. Verified programmatically to be exactly 64
// hex characters (see the sibling crypto package's own test key for the
// same verification approach, adopted after an earlier truncated-by-one-
// character copy/paste mistake there).
const validKeyHex = "9b59710ad1456cbfe978217adf51bf7e60f649a9fee925e5f30abcc2a02eaf3b"

func TestValidateMasterKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
		errSub  string
	}{
		{"valid key", validKeyHex, false, ""},
		{"empty is required", "", true, "required"},
		{"not hex", "not-a-hex-string-at-all-not-a-hex-string-at-all-not-a-hex-str", true, "hex string"},
		{"too short", "deadbeef", true, "32 bytes"},
		{"odd-length hex (invalid encoding)", validKeyHex[:63], true, "hex string"},
		{"too long", validKeyHex + "ff", true, "32 bytes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMasterKey(tc.key)
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

// validateModulePIIKey mirrors validateMasterKey's hex/length check, but
// treats empty as valid (nil error) - the one behavioral difference between
// the two, since MODULAB_MODULE_PII_KEY is optional.
func TestValidateModulePIIKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid key", validKeyHex, false},
		{"empty is valid (optional key)", "", false},
		{"not hex", "not-a-hex-string-at-all-not-a-hex-string-at-all-not-a-hex-str", true},
		{"too short", "deadbeef", true},
		{"too long", validKeyHex + "ff", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModulePIIKey(tc.key)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}
