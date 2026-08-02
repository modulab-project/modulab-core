package crypto

import (
	"testing"
)

// testKeyHex is a syntactically valid 32-byte (64 hex char) master key, used
// only in tests - never a real key.
const testKeyHex = "98316afea7e60e50bc4a7abea5141508af96db9a88e38a57f3cd4ae673936793"

// A different valid key, used to prove Decrypt fails when the key doesn't
// match the one Encrypt used - the exact class of bug the news-feed
// encryption incident (referenced by the audit, A-1 #3) would have caught.
const otherKeyHex = "b4954da5cdb62aca677773ab2ad970e4c0512b1dae2ab8f1d9ad313d79ec6a75"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cases := []string{
		"",
		"hello",
		"a very very very long plaintext string that is much longer than a single AES block, to make sure multi-block payloads round-trip too",
		"unicode: äöü ß 日本語 🎉",
		"line\nbreaks\tand\ttabs",
	}
	for _, plain := range cases {
		t.Run(plain, func(t *testing.T) {
			enc, err := Encrypt(testKeyHex, plain)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if enc == plain && plain != "" {
				t.Fatalf("ciphertext equals plaintext - not actually encrypted")
			}
			got, err := Decrypt(testKeyHex, enc)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if got != plain {
				t.Fatalf("round trip mismatch: got %q, want %q", got, plain)
			}
		})
	}
}

// GCM nonces must be random per call - two Encrypt calls on the same
// plaintext under the same key must not produce the same ciphertext, or the
// scheme silently degrades to something an attacker can fingerprint/replay.
func TestEncrypt_NonceIsRandomPerCall(t *testing.T) {
	a, err := Encrypt(testKeyHex, "same plaintext")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := Encrypt(testKeyHex, "same plaintext")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if a == b {
		t.Fatalf("two Encrypt calls on identical plaintext produced identical ciphertext - nonce reuse")
	}
	// Both must still decrypt to the same plaintext despite differing.
	da, err := Decrypt(testKeyHex, a)
	if err != nil {
		t.Fatalf("Decrypt(a): %v", err)
	}
	db, err := Decrypt(testKeyHex, b)
	if err != nil {
		t.Fatalf("Decrypt(b): %v", err)
	}
	if da != db || da != "same plaintext" {
		t.Fatalf("decrypted values diverged: %q vs %q", da, db)
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	enc, err := Encrypt(testKeyHex, "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(otherKeyHex, enc); err == nil {
		t.Fatalf("expected Decrypt with the wrong key to fail, got nil error")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	enc, err := Encrypt(testKeyHex, "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Flip a character in the middle of the base64 blob - GCM's auth tag
	// must catch this rather than silently returning garbage plaintext.
	tampered := []byte(enc)
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}
	if _, err := Decrypt(testKeyHex, string(tampered)); err == nil {
		t.Fatalf("expected Decrypt of tampered ciphertext to fail, got nil error")
	}
}

func TestDecrypt_TooShortOrInvalidInput(t *testing.T) {
	if _, err := Decrypt(testKeyHex, "not-valid-base64!!!"); err == nil {
		t.Fatalf("expected error for invalid base64 input")
	}
	if _, err := Decrypt(testKeyHex, ""); err == nil {
		t.Fatalf("expected error for empty (too-short) ciphertext")
	}
}

func TestBuildGCM_RejectsWrongKeyLength(t *testing.T) {
	if _, err := Encrypt("deadbeef", "x"); err == nil {
		t.Fatalf("expected error for a key that isn't 32 raw bytes")
	}
	if _, err := Encrypt("not-hex-at-all", "x"); err == nil {
		t.Fatalf("expected error for a key that isn't valid hex")
	}
}

func TestEncryptIfNotEmpty_DecryptIfNotEmpty(t *testing.T) {
	enc, err := EncryptIfNotEmpty(testKeyHex, "")
	if err != nil {
		t.Fatalf("EncryptIfNotEmpty(empty): %v", err)
	}
	if enc != "" {
		t.Fatalf("EncryptIfNotEmpty(empty) = %q, want empty string unchanged", enc)
	}

	plain, err := DecryptIfNotEmpty(testKeyHex, "")
	if err != nil {
		t.Fatalf("DecryptIfNotEmpty(empty): %v", err)
	}
	if plain != "" {
		t.Fatalf("DecryptIfNotEmpty(empty) = %q, want empty string unchanged", plain)
	}

	enc, err = EncryptIfNotEmpty(testKeyHex, "value")
	if err != nil {
		t.Fatalf("EncryptIfNotEmpty: %v", err)
	}
	if enc == "value" {
		t.Fatalf("EncryptIfNotEmpty did not actually encrypt")
	}
	got, err := DecryptIfNotEmpty(testKeyHex, enc)
	if err != nil {
		t.Fatalf("DecryptIfNotEmpty: %v", err)
	}
	if got != "value" {
		t.Fatalf("round trip via *IfNotEmpty: got %q, want %q", got, "value")
	}
}
