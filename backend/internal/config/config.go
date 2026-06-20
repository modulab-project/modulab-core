// Package config loads modulab-core's runtime configuration from environment
// variables. See .env.example at the repository root for the full list of
// supported variables and spec section 2.4 for MODULAB_MASTER_KEY semantics.
package config

import (
	"fmt"
	"os"
)

// Config holds all environment-derived settings for a single Core process.
// Fields mirror .env.example one-to-one so the mapping stays obvious.
type Config struct {
	MasterKey         string
	BootstrapTokenTTL string

	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string

	ValkeyHost string
	ValkeyPort string

	DenoSocketPath string
	DenoBinaryPath string

	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string

	GroupPrefix string

	// HTTPAddr is not part of .env.example yet; it defaults to :8080 and can
	// be overridden for local development without touching the documented
	// env surface.
	HTTPAddr string
}

// Load reads configuration from the process environment. It does not
// validate cross-field invariants (e.g. OIDC completeness) - that happens
// once the Setup Wizard is implemented, since an empty OIDC config is a
// valid pre-setup state.
func Load() (Config, error) {
	cfg := Config{
		MasterKey:         os.Getenv("MODULAB_MASTER_KEY"),
		BootstrapTokenTTL: getEnvDefault("MODULAB_BOOTSTRAP_TOKEN_TTL", "24h"),

		DBHost:     getEnvDefault("MODULAB_DB_HOST", "localhost"),
		DBPort:     getEnvDefault("MODULAB_DB_PORT", "6432"),
		DBName:     getEnvDefault("MODULAB_DB_NAME", "modulab"),
		DBUser:     getEnvDefault("MODULAB_DB_USER", "modulab"),
		DBPassword: os.Getenv("MODULAB_DB_PASSWORD"),

		ValkeyHost: getEnvDefault("MODULAB_VALKEY_HOST", "localhost"),
		ValkeyPort: getEnvDefault("MODULAB_VALKEY_PORT", "6379"),

		DenoSocketPath: getEnvDefault("MODULAB_DENO_SOCKET_PATH", "/tmp/modulab-deno.sock"),
		DenoBinaryPath: getEnvDefault("MODULAB_DENO_BINARY_PATH", "/usr/local/bin/deno"),

		OIDCIssuerURL:    os.Getenv("MODULAB_OIDC_ISSUER_URL"),
		OIDCClientID:     os.Getenv("MODULAB_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("MODULAB_OIDC_CLIENT_SECRET"),

		GroupPrefix: getEnvDefault("MODULAB_GROUP_PREFIX", "modulab_"),

		HTTPAddr: getEnvDefault("MODULAB_HTTP_ADDR", ":8080"),
	}

	if cfg.GroupPrefix == "" {
		return Config{}, fmt.Errorf("MODULAB_GROUP_PREFIX must not be empty (spec section 3.3 hard gate)")
	}

	return cfg, nil
}

func getEnvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
