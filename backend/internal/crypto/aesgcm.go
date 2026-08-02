// Package crypto provides AES-256-GCM encryption for secrets that must be
// stored at rest. Spec section 2.3 classifies OIDC client secrets and
// private keys as "critical" and mandates AES-GCM for them. The key is
// always ModuLab Core's master key (spec section 2.4): a 64-character hex
// string decoding to 32 raw bytes.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

// gcmCache caches the built cipher.AEAD per key (keyed by the hex string
// itself) so Encrypt/Decrypt don't redo hex.DecodeString + aes.NewCipher +
// cipher.NewGCM on every single call - in practice there is only ever one
// distinct key (the master key), so this cache stays at size 1, but every
// encrypt/decrypt call across the whole app (session tokens, SMTP
// credentials, OIDC secrets, module PII, ...) was paying that setup cost
// repeatedly for no reason. sync.Map is safe for concurrent
// read-mostly/write-rarely use per its own doc comment, which matches this
// access pattern exactly. Only the AEAD *setup* is cached here - the actual
// Seal/Open calls still happen fresh per call, same as before.
var gcmCache sync.Map // keyHex (string) -> cipher.AEAD

func newGCM(keyHex string) (cipher.AEAD, error) {
	if cached, ok := gcmCache.Load(keyHex); ok {
		return cached.(cipher.AEAD), nil
	}
	gcm, err := buildGCM(keyHex)
	if err != nil {
		return nil, err
	}
	actual, _ := gcmCache.LoadOrStore(keyHex, gcm)
	return actual.(cipher.AEAD), nil
}

// Encrypt encrypts plaintext with AES-256-GCM under keyHex and returns a
// base64-encoded nonce||ciphertext blob suitable for storing in a TEXT
// column.
func Encrypt(keyHex, plaintext string) (string, error) {
	gcm, err := newGCM(keyHex)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func Decrypt(keyHex, encoded string) (string, error) {
	gcm, err := newGCM(keyHex)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: decode: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("crypto: ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt: %w", err)
	}
	return string(plaintext), nil
}

// EncryptIfNotEmpty encrypts plaintext only when it is non-empty, returning
// the empty string unchanged. Callers that store optional fields (e.g.
// smtp_username on an unauthenticated relay) can use this instead of
// branching on emptiness themselves.
func EncryptIfNotEmpty(keyHex, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	return Encrypt(keyHex, plaintext)
}

// DecryptIfNotEmpty reverses EncryptIfNotEmpty: an empty encoded string is
// returned as-is without attempting a base64 decode.
func DecryptIfNotEmpty(keyHex, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	return Decrypt(keyHex, encoded)
}

func buildGCM(keyHex string) (cipher.AEAD, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes (256 bit), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return gcm, nil
}
