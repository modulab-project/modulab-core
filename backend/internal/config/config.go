// Package config loads modulab-core's runtime configuration from environment
// variables. See .env.example at the repository root for the full list of
// supported variables and spec section 2.4 for MODULAB_MASTER_KEY semantics.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Config holds all environment-derived settings for a single Core process.
// Fields mirror .env.example one-to-one so the mapping stays obvious.
type Config struct {
	// MasterKey (MODULAB_MASTER_KEY) is the AES-256 key (64 hex chars, 32
	// raw bytes) used to encrypt the OIDC client secret and DNS-challenge
	// provider credentials before they touch Postgres (internal/crypto).
	// It must come from the environment - Load fails outright if it is
	// missing or the wrong shape (see validateMasterKey) rather than
	// generating one and falling back to a copy persisted in core_settings,
	// which earlier versions of Core did. That fallback meant the key
	// protecting the encrypted columns sat in plaintext in the same
	// database, right next to what it protects - removed 2026-06-21 on
	// request, once that was pointed out as the actual security boundary
	// it undermines. Generate one with `openssl rand -hex 32`.
	MasterKey         string
	BootstrapTokenTTL string

	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string

	ValkeyHost     string
	ValkeyPort     string
	ValkeyPassword string

	DenoSocketPath string
	DenoBinaryPath string

	// ModuleDataDir (MODULAB_MODULE_DATA_DIR) is where installed module files
	// are stored on disk. Each module gets a sub-directory: {ModuleDataDir}/{name}.
	// Default: /var/lib/modulab/modules
	ModuleDataDir string

	// CosignBinaryPath (MODULAB_COSIGN_BINARY_PATH) is the path to the cosign
	// binary used to verify official module signatures. Defaults to searching
	// $PATH for "cosign". Set to "" to use the default.
	CosignBinaryPath string

	// PublicBaseURL is what Core tells the OIDC provider to redirect back
	// to after login (".../v1/auth/callback") - it has to be the externally
	// reachable URL, not HTTPAddr, since those differ behind a reverse
	// proxy (Traefik, in production).
	PublicBaseURL string

	// FrontendBaseURL is where the SPA is served from. In production this
	// is typically the same as PublicBaseURL (Core serves the built
	// frontend itself, so there is only one origin) - it exists as its own
	// variable rather than always reusing PublicBaseURL because local dev
	// runs the frontend on Vite's own dev server (a different port,
	// typically :5173) so its hot-reload/HMR keeps working, and
	// auth.CallbackHandler needs to know that's where to send the browser
	// back to instead.
	FrontendBaseURL string

	// HTTPAddr is not part of .env.example yet; it defaults to :8080 and can
	// be overridden for local development without touching the documented
	// env surface.
	HTTPAddr string
}

// Load reads configuration from the process environment. Before reading any
// variable, it fills gaps from a local .env file if one exists (checking
// both ./.env and ../.env, to support running `go run ./cmd/core` from
// either the backend/ directory or the repository root). Real environment
// variables that are already set always take precedence over .env content -
// this is meant for local development convenience only; production deploys
// set real environment variables via docker-compose's env_file directive.
//
// MODULAB_MASTER_KEY is the one variable Load validates and fails outright
// on if missing or malformed, rather than letting Core start with no way to
// encrypt secrets - see the MasterKey field's doc comment for why. Neither
// OIDC configuration nor the group prefix have an environment-variable path
// at all anymore (group prefix removed 2026-06-21 alongside OIDC, on
// request: "keine Daten außer wirklich benötigte in der .env" - both are
// non-secret values the Setup Wizard already persists, so duplicating them
// in .env was redundant surface, not a real requirement like the master
// key or the DB/Valkey connection settings are). See
// setup.ResolveOIDCConfig and setup.ResolveGroupPrefix, both DB-only now.
func Load() (Config, error) {
	loadDotEnvFiles()

	masterKey := os.Getenv("MODULAB_MASTER_KEY")
	if err := validateMasterKey(masterKey); err != nil {
		return Config{}, err
	}

	cfg := Config{
		MasterKey:         masterKey,
		BootstrapTokenTTL: getEnvDefault("MODULAB_BOOTSTRAP_TOKEN_TTL", "24h"),

		DBHost:     getEnvDefault("MODULAB_DB_HOST", "localhost"),
		DBPort:     getEnvDefault("MODULAB_DB_PORT", "6432"),
		DBName:     getEnvDefault("MODULAB_DB_NAME", "modulab"),
		DBUser:     getEnvDefault("MODULAB_DB_USER", "modulab"),
		DBPassword: os.Getenv("MODULAB_DB_PASSWORD"),

		ValkeyHost:     getEnvDefault("MODULAB_VALKEY_HOST", "localhost"),
		ValkeyPort:     getEnvDefault("MODULAB_VALKEY_PORT", "6379"),
		ValkeyPassword: os.Getenv("MODULAB_VALKEY_PASSWORD"),

		DenoSocketPath: getEnvDefault("MODULAB_DENO_SOCKET_PATH", "/tmp/modulab-deno.sock"),
		DenoBinaryPath: getEnvDefault("MODULAB_DENO_BINARY_PATH", "/usr/local/bin/deno"),

		ModuleDataDir:    getEnvDefault("MODULAB_MODULE_DATA_DIR", "/var/lib/modulab/modules"),
		CosignBinaryPath: os.Getenv("MODULAB_COSIGN_BINARY_PATH"), // "" = search $PATH

		PublicBaseURL: getEnvDefault("MODULAB_PUBLIC_BASE_URL", "http://localhost:8080"),

		// Defaults to Vite's standard dev-server port, not PublicBaseURL's
		// default - the two are deliberately different out of the box so a
		// fresh `npm run dev` + `go run ./cmd/core` pairing works without
		// any .env edits.
		FrontendBaseURL: getEnvDefault("MODULAB_FRONTEND_BASE_URL", "http://localhost:5173"),

		HTTPAddr: getEnvDefault("MODULAB_HTTP_ADDR", ":8080"),
	}

	return cfg, nil
}

// validateMasterKey fails fast and specifically: an operator who forgot to
// set MODULAB_MASTER_KEY, or pasted a truncated/non-hex value, gets a clear
// startup error pointing at the exact env var rather than either a generic
// crypto error much later (the first time something tries to encrypt or
// decrypt) or - the behavior this replaces - Core silently generating and
// persisting a key on its own.
func validateMasterKey(key string) error {
	if key == "" {
		return fmt.Errorf("config: MODULAB_MASTER_KEY is required and must be set in the environment or .env - generate one with `openssl rand -hex 32`; Core no longer generates or persists a fallback key to the database")
	}
	raw, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("config: MODULAB_MASTER_KEY must be a hex string: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("config: MODULAB_MASTER_KEY must decode to 32 bytes (64 hex characters), got %d bytes", len(raw))
	}
	return nil
}

func getEnvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadDotEnvFiles fills process environment gaps from .env / ../.env. It is
// intentionally forgiving: a missing file, an unreadable file, or malformed
// lines are all silently skipped rather than treated as fatal, since this
// path only ever supplies *additional* defaults on top of the real
// environment.
func loadDotEnvFiles() {
	for _, path := range []string{".env", "../.env"} {
		applyDotEnvFile(path)
	}
}

func applyDotEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		// Strip a trailing inline comment ("KEY=value  # comment") before
		// trimming. This is a deliberately simple heuristic - it does not
		// understand quoting, so a value that legitimately contains "#"
		// will be truncated. Acceptable for this dev-convenience loader;
		// .env.example avoids "#" inside real values for this reason.
		if idx := strings.Index(value, "#"); idx != -1 {
			value = value[:idx]
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue // real environment variables always win over .env content
		}
		_ = os.Setenv(key, value)
	}
}
