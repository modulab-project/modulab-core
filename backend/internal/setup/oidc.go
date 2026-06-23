// This file implements the Setup Wizard's OIDC configuration step (spec
// section 6.5, wizard steps 2-3): the operator picks a provider and enters
// Issuer URL, Client ID, and Client Secret. The secret is encrypted at rest
// with the master key before being persisted, since spec section 2.3
// classifies OIDC client secrets as critical (AES-GCM).
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const (
	oidcIssuerSettingKey       = "oidc_issuer_url"
	oidcClientIDSettingKey     = "oidc_client_id"
	oidcClientSecretSettingKey = "oidc_client_secret_enc"
)

// OIDCConfigRequest is the body of POST /v1/setup/oidc/configure.
type OIDCConfigRequest struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// OIDCStatusResponse reports the non-secret half of the OIDC configuration.
// ClientSecret is intentionally never included here or anywhere else once
// it has been written - InitHandler-style "return it once" does not apply
// to a value the operator already has in their IdP, unlike the generated
// master key.
type OIDCStatusResponse struct {
	Configured bool   `json:"configured"`
	IssuerURL  string `json:"issuer_url,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
}

// OIDCRuntimeConfig is the fully resolved OIDC configuration the login flow
// (internal/auth) needs to talk to the IdP. Unlike OIDCStatusResponse, this
// is never serialized to an HTTP response: ClientSecret has already been
// decrypted, so callers must not log it.
type OIDCRuntimeConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
}

// ResolveOIDCConfig returns the effective OIDC configuration as persisted by
// /v1/setup/oidc/configure (steps 2-3), with all three fields decrypted using
// masterKey. IssuerURL and ClientID are Class B (GCM) just like the secret -
// none of these values should appear in a DB dump in plaintext (spec section
// 2.4). Called by the login flow on every /v1/auth/login and
// /v1/auth/callback request, so a provider configured through the wizard
// works immediately, without a Core restart.
func ResolveOIDCConfig(ctx context.Context, pool *db.Pool, masterKey string) (OIDCRuntimeConfig, error) {
	encIssuer, exists, err := pool.GetSetting(ctx, oidcIssuerSettingKey)
	if err != nil {
		return OIDCRuntimeConfig{}, err
	}
	if !exists {
		return OIDCRuntimeConfig{}, fmt.Errorf("setup: oidc has not been configured yet (call /v1/setup/oidc/configure first)")
	}
	issuer, err := crypto.Decrypt(masterKey, encIssuer)
	if err != nil {
		return OIDCRuntimeConfig{}, fmt.Errorf("setup: decrypt oidc_issuer_url: %w", err)
	}
	encClientID, _, err := pool.GetSetting(ctx, oidcClientIDSettingKey)
	if err != nil {
		return OIDCRuntimeConfig{}, err
	}
	clientID, err := crypto.Decrypt(masterKey, encClientID)
	if err != nil {
		return OIDCRuntimeConfig{}, fmt.Errorf("setup: decrypt oidc_client_id: %w", err)
	}
	encryptedSecret, _, err := pool.GetSetting(ctx, oidcClientSecretSettingKey)
	if err != nil {
		return OIDCRuntimeConfig{}, err
	}
	secret, err := crypto.Decrypt(masterKey, encryptedSecret)
	if err != nil {
		return OIDCRuntimeConfig{}, fmt.Errorf("setup: decrypt oidc client secret: %w", err)
	}
	return OIDCRuntimeConfig{IssuerURL: issuer, ClientID: clientID, ClientSecret: secret}, nil
}

// IssuerURL returns just the configured OIDC issuer URL. masterKey is
// required to decrypt it, since oidc_issuer_url is now stored as GCM
// ciphertext alongside the other OIDC fields (spec section 2.4). For callers
// that only need to build a link to the IdP (e.g. MeHandler's
// account_settings_url) and have no use for ClientID/ClientSecret, this
// avoids decrypting the other two fields unnecessarily. ok is false if OIDC
// has not been configured yet.
func IssuerURL(ctx context.Context, pool *db.Pool, masterKey string) (string, bool, error) {
	enc, exists, err := pool.GetSetting(ctx, oidcIssuerSettingKey)
	if err != nil || !exists {
		return "", exists, err
	}
	issuer, err := crypto.Decrypt(masterKey, enc)
	if err != nil {
		return "", false, fmt.Errorf("setup: decrypt oidc_issuer_url: %w", err)
	}
	return issuer, true, nil
}

// OIDCConfigured reports whether the OIDC provider has already been
// configured, without exposing the underlying setting key to callers
// outside this package. Used by main.go's startup log to summarize Setup
// Wizard progress.
func OIDCConfigured(ctx context.Context, pool *db.Pool) (bool, error) {
	_, exists, err := pool.GetSetting(ctx, oidcIssuerSettingKey)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// OIDCStatusHandler reports whether OIDC has been configured, and if so,
// the issuer URL and client ID (never the client secret). masterKey is
// required to decrypt the stored ciphertext values for display (spec section
// 2.4: oidc_issuer_url and oidc_client_id are both GCM-encrypted at rest).
func OIDCStatusHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		encIssuer, exists, err := pool.GetSetting(ctx, oidcIssuerSettingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, OIDCStatusResponse{Configured: false})
			return
		}
		issuer, err := crypto.Decrypt(masterKey, encIssuer)
		if err != nil {
			http.Error(w, fmt.Sprintf("decrypt oidc_issuer_url: %v", err), http.StatusInternalServerError)
			return
		}

		encClientID, _, err := pool.GetSetting(ctx, oidcClientIDSettingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		clientID, err := crypto.Decrypt(masterKey, encClientID)
		if err != nil {
			http.Error(w, fmt.Sprintf("decrypt oidc_client_id: %v", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, OIDCStatusResponse{
			Configured: true,
			IssuerURL:  issuer,
			ClientID:   clientID,
		})
	}
}

// OIDCConfigureHandler validates and persists the OIDC provider
// configuration. masterKey must already be resolved (see
// ResolveMasterKey) - it is the AES-256 key used to encrypt ClientSecret
// before it ever touches the database.
//
// This step does not perform OIDC discovery against the issuer yet (spec
// section 6.5 steps 2-3 only require storing what the operator enters).
// Validating that the issuer is reachable and OIDC-conformant belongs with
// the login flow itself (spec section 3.3), since that is where discovery
// is actually exercised - tracked as a follow-up, not done here to keep
// this commit reviewable.
func OIDCConfigureHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req OIDCConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		req.IssuerURL = strings.TrimSpace(req.IssuerURL)
		req.ClientID = strings.TrimSpace(req.ClientID)

		if req.IssuerURL == "" || req.ClientID == "" || req.ClientSecret == "" {
			http.Error(w, "issuer_url, client_id, and client_secret are all required", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(req.IssuerURL, "https://") && !strings.HasPrefix(req.IssuerURL, "http://") {
			http.Error(w, "issuer_url must be an absolute http(s) URL", http.StatusBadRequest)
			return
		}

		encIssuer, err := crypto.Encrypt(masterKey, req.IssuerURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		encClientID, err := crypto.Encrypt(masterKey, req.ClientID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		encryptedSecret, err := crypto.Encrypt(masterKey, req.ClientSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		if err := pool.SetSetting(ctx, oidcIssuerSettingKey, encIssuer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(ctx, oidcClientIDSettingKey, encClientID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(ctx, oidcClientSecretSettingKey, encryptedSecret); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, OIDCStatusResponse{
			Configured: true,
			IssuerURL:  req.IssuerURL,
			ClientID:   req.ClientID,
		})
	}
}
