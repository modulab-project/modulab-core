// Package modules implements the full module lifecycle: installation, updates,
// uninstallation, verification, status tracking and Deno Worker management
// (spec sections 4.3, 4.6–4.9, 4.11).
package modules

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

// officialPublicKey is the production Cosign public key embedded at build
// time from cosign_pubkey.pem (confirmed 2026-07-05: real key, not a
// placeholder). VerifyCosign still checks for the PEM header defensively -
// if this file is ever replaced with a placeholder/comment-only version
// during local development, verification degrades to ErrNoPublicKey rather
// than failing in some less obvious way.
//
//go:embed cosign_pubkey.pem
var officialPublicKey string

// ErrNoPublicKey is returned by VerifyCosign when the embedded key doesn't
// contain a PEM header (e.g. a local dev checkout with a placeholder file).
var ErrNoPublicKey = fmt.Errorf("modules: official Cosign public key not configured (cosign_pubkey.pem has no PEM header)")

// CosignBinaryPath is the default location of the cosign binary. Override via
// the MODULAB_COSIGN_BINARY_PATH environment variable (read by config.Load).
// Falls back to searching $PATH when left at the default.
const CosignBinaryDefault = "cosign"

// VerifyResult summarises what was checked for a downloaded module.zip.
type VerifyResult struct {
	// SHA256 is the hex digest that was computed and matched.
	SHA256 string
	// CosignVerified is true when the Cosign signature was checked and passed.
	CosignVerified bool
	// CosignSkipped is true when Cosign was not checked (community module
	// without a .sig file, or public key placeholder not yet configured).
	CosignSkipped bool
}

// VerifySHA256 reads zipPath, computes its SHA-256 digest, and compares it
// against expectedHex (case-insensitive). Returns an error on mismatch.
// This is always called — for every module source, every install/update.
func VerifySHA256(zipPath, expectedHex string) (string, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return "", fmt.Errorf("modules: verify sha256: open %q: %w", zipPath, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("modules: verify sha256: close %s: %v", zipPath, err)
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("modules: verify sha256: hash %q: %w", zipPath, err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expectedHex) {
		return "", fmt.Errorf("modules: sha256 mismatch for %q: got %s, expected %s",
			zipPath, got, expectedHex)
	}
	return got, nil
}

// VerifyCosign verifies the Cosign blob signature of zipPath against the
// embedded official public key. bundlePath is the local path to the downloaded
// Sigstore bundle file (JSON, produced by `cosign sign-blob --bundle`).
// cosignBin is the path to the cosign binary (use CosignBinaryDefault
// when empty).
//
// Returns:
//   - (true, nil)          — signature verified OK
//   - (false, ErrNoPublicKey) — embedded key is still the placeholder
//   - (false, err)         — signature check failed or cosign not found
//
// For official modules this must return (true, nil) before installation proceeds.
// Community modules may choose to call this and present a ✅/⚠️ badge based on
// the result rather than blocking installation.
func VerifyCosign(zipPath, bundlePath, cosignBin string) (bool, error) {
	if cosignBin == "" {
		cosignBin = CosignBinaryDefault
	}

	// Guard: refuse to verify if the embedded key is still the placeholder.
	if !strings.Contains(officialPublicKey, "-----BEGIN PUBLIC KEY-----") {
		return false, ErrNoPublicKey
	}

	// Write the embedded public key to a temp file so cosign can read it.
	keyFile, err := os.CreateTemp("", "modulab-cosign-pubkey-*.pem")
	if err != nil {
		return false, fmt.Errorf("modules: cosign: create temp key file: %w", err)
	}
	defer func() {
		// Best-effort: keyFile is already explicitly closed above before
		// cosign runs, so this second Close() is expected to no-op (or
		// report "already closed") on the success path - only logged in
		// case an early-return above skipped the explicit close.
		if err := keyFile.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			log.Printf("modules: cosign: close temp key file: %v", err)
		}
		if err := os.Remove(keyFile.Name()); err != nil {
			log.Printf("modules: cosign: remove temp key file %s: %v", keyFile.Name(), err)
		}
	}()

	if _, err := keyFile.WriteString(officialPublicKey); err != nil {
		return false, fmt.Errorf("modules: cosign: write key: %w", err)
	}
	// Closed explicitly (rather than relying on the deferred close above)
	// so the write is flushed to disk before cosign reads the file below -
	// a failure here means the key file may be incomplete and verification
	// must not proceed against it.
	if err := keyFile.Close(); err != nil {
		return false, fmt.Errorf("modules: cosign: close temp key file: %w", err)
	}

	// cosign verify-blob --key <pubkey> --bundle <bundle> <zip>
	cmd := exec.Command(cosignBin,
		"verify-blob",
		"--key", keyFile.Name(),
		"--bundle", bundlePath,
		zipPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("modules: cosign verify-blob failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	log.Printf("modules: cosign: verified %q OK", zipPath)
	return true, nil
}

// CosignAvailable reports whether the cosign binary is reachable at cosignBin
// (or on $PATH when cosignBin is empty). Used to show the correct badge in the
// Store UI without trying a full verification.
func CosignAvailable(cosignBin string) bool {
	if cosignBin == "" {
		cosignBin = CosignBinaryDefault
	}
	_, err := exec.LookPath(cosignBin)
	return err == nil
}
