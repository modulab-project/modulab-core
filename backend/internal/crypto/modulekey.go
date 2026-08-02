package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// DeriveModuleKey derives a per-module AES-256 key from Core's shared
// MODULAB_MODULE_PII_KEY (rawKeyHex) and moduleName, so a compromised
// module can no longer decrypt another module's PII with the one key every
// Tier 2/3 worker used to receive verbatim (2026-08-02 security audit,
// M-1). Every module gets a distinct, unrelated 32-byte subkey derived from
// the same root key - the standard single-root-key-per-tenant construction.
//
// This is HKDF-Expand (RFC 5869) with rawKeyHex's decoded bytes used
// directly as the pseudorandom key, skipping HKDF-Extract - RFC 5869 §3.3
// explicitly allows this when the input key material is already a
// uniformly random key of the hash's output length, which
// MODULAB_MODULE_PII_KEY is by construction (config.validateModulePIIKey
// requires exactly 32 securely-random bytes, hex-encoded, same as
// MODULAB_MASTER_KEY). Only a single expansion block is computed
// (T(1) = HMAC-SHA256(PRK, info || 0x01)) because that block is already 32
// bytes - exactly the AES-256 key size this needs - so there is no T(2) to
// concatenate. Implemented directly against crypto/hmac + crypto/sha256
// (both stdlib) rather than pulling in golang.org/x/crypto/hkdf for what
// is, at this key size, a single HMAC call.
//
// rawKeyHex must be the same 64-hex-char / 32-byte format
// config.validateModulePIIKey already enforces at Core startup; a
// malformed value fails here with a clear error rather than deriving a
// key from garbage.
func DeriveModuleKey(rawKeyHex, moduleName string) (string, error) {
	raw, err := hex.DecodeString(rawKeyHex)
	if err != nil {
		return "", fmt.Errorf("crypto: derive module key: decode root key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("crypto: derive module key: root key must be 32 bytes (256 bit), got %d", len(raw))
	}
	if moduleName == "" {
		return "", fmt.Errorf("crypto: derive module key: empty module name")
	}

	// info binds the derived key to exactly this module name and to a
	// versioned, fixed label (modulab-module-pii-v1) - if the derivation
	// scheme ever needs to change in an incompatible way, bumping the
	// label produces an entirely unrelated set of subkeys rather than
	// silently colliding with the v1 ones.
	info := []byte("modulab-module-pii-v1:" + moduleName)
	mac := hmac.New(sha256.New, raw)
	mac.Write(info)
	mac.Write([]byte{0x01}) // HKDF block counter for T(1)
	sub := mac.Sum(nil)     // 32 bytes - sha256.Size, exactly one AES-256 key
	return hex.EncodeToString(sub), nil
}
