// This file implements the Setup Wizard's DNS-challenge-provider step (spec
// section 6.5 step 4): the operator picks a DNS provider and enters that
// provider's API credentials, used by Traefik/Let's Encrypt to complete a
// DNS-01 challenge for production TLS certificates.
//
// This is deliberately a configuration-only placeholder: nothing in Core
// actually talks to the chosen provider yet (no Traefik integration, no
// certificate issuance). It exists so the wizard's step sequence matches the
// spec and so the credentials are captured and encrypted at rest from day
// one, rather than bolting persistence on later once Traefik wiring lands.
//
// It is mandatory, with no skip option in the frontend, even though it has
// no real effect locally yet: an earlier version of this step was
// skippable, which just moved the problem to step 7 silently refusing to
// complete - making it mandatory here means the operator configures and
// tests it for real during setup, not "eventually, maybe".
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
	dnsChallengeProviderSettingKey    = "dns_challenge_provider"
	dnsChallengeCredentialsSettingKey = "dns_challenge_credentials_enc"
)

// DNSChallengeConfigRequest is the body of POST /v1/setup/dns-challenge/configure.
// Credentials is an opaque, provider-defined blob (e.g. a JSON object with
// whatever fields that provider's API needs) rather than a fixed set of
// fields - different DNS providers need different credential shapes (a
// single API token vs. an access-key/secret-key pair vs. a zone ID plus
// token), and Core does not validate or interpret it yet since nothing
// consumes it.
type DNSChallengeConfigRequest struct {
	Provider    string `json:"provider"`
	Credentials string `json:"credentials"`
}

// DNSChallengeStatusResponse reports the non-secret half of the
// configuration. Credentials is intentionally never included, mirroring
// OIDCStatusResponse's treatment of the client secret.
type DNSChallengeStatusResponse struct {
	Configured bool   `json:"configured"`
	Provider   string `json:"provider,omitempty"`
}

// DNSChallengeConfigured reports whether a DNS-challenge provider has
// already been configured. Used by main.go's startup log and by
// CompleteHandler's step-7 completeness check.
func DNSChallengeConfigured(ctx context.Context, pool *db.Pool) (bool, error) {
	_, exists, err := pool.GetSetting(ctx, dnsChallengeProviderSettingKey)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// DNSChallengeStatusHandler reports whether a DNS-challenge provider has
// been configured, and if so, which one (never the credentials).
func DNSChallengeStatusHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider, exists, err := pool.GetSetting(r.Context(), dnsChallengeProviderSettingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, DNSChallengeStatusResponse{Configured: false})
			return
		}
		writeJSON(w, http.StatusOK, DNSChallengeStatusResponse{
			Configured: true,
			Provider:   provider,
		})
	}
}

// DNSChallengeConfigureHandler validates and persists the DNS-challenge
// provider configuration. masterKey must already be resolved (see
// ResolveMasterKey) - Credentials is encrypted with it before ever touching
// the database, exactly like the OIDC client secret in oidc.go.
func DNSChallengeConfigureHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req DNSChallengeConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		req.Provider = strings.TrimSpace(req.Provider)
		if req.Provider == "" || req.Credentials == "" {
			http.Error(w, "provider and credentials are both required", http.StatusBadRequest)
			return
		}

		encryptedCredentials, err := crypto.Encrypt(masterKey, req.Credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		if err := pool.SetSetting(ctx, dnsChallengeProviderSettingKey, req.Provider); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(ctx, dnsChallengeCredentialsSettingKey, encryptedCredentials); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, DNSChallengeStatusResponse{
			Configured: true,
			Provider:   req.Provider,
		})
	}
}
