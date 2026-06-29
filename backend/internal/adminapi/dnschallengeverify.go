package adminapi

// DNS-challenge credential verification (POST /v1/admin/dns-challenge/verify).
//
// Reads the stored provider + credentials from core_settings, then fires a
// lightweight read-only request against the provider's API to confirm the key
// is valid. Providers without a simple token-ping endpoint are reported as
// "not supported" rather than silently skipped.
//
// Supported providers and their ping strategy:
//
//	cloudflare   GET /client/v4/user/tokens/verify       Bearer token
//	hetzner      GET /api/v1/zones                       Auth-API-Token header
//	digitalocean GET /v2/account                         Bearer token
//	linode       GET /v4/profile                         Bearer token
//	vultr        GET /v2/account                         Authorization: Token
//	dnsimple     GET /v2/whoami                          Bearer token
//	gandi        GET /v5/livedns/domains                 Authorization: Apikey
//	porkbun      POST /api/json/v3/ping                  JSON body {apikey, secretapikey}
//
// Unsupported (stored but not verified):
//
//	route53, inwx, namecheap, ovh, azure, google, njalla, __custom__

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// DNSVerifyResponse is returned by POST /v1/admin/dns-challenge/verify.
type DNSVerifyResponse struct {
	// Valid is true when the provider accepted the credentials.
	Valid bool `json:"valid"`
	// Supported is false when no ping strategy exists for this provider.
	Supported bool `json:"supported"`
	// Message is a human-readable result or error detail.
	Message string `json:"message"`
}

// DNSChallengeVerifyHandler serves POST /v1/admin/dns-challenge/verify.
// It reads the currently stored provider + credentials and pings the provider API.
func DNSChallengeVerifyHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		// Load provider.
		encProvider, providerExists, err := pool.GetSetting(ctx, "dns_challenge_provider")
		if err != nil || !providerExists || encProvider == "" {
			http.Error(w, "dns challenge not configured", http.StatusBadRequest)
			return
		}
		provider, err := crypto.DecryptIfNotEmpty(masterKey, encProvider)
		if err != nil {
			http.Error(w, "decrypt provider: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Load credentials (optional for some providers, but needed for all we verify).
		var credentials string
		encCreds, credsExist, err := pool.GetSetting(ctx, "dns_challenge_credentials_enc")
		if err != nil {
			http.Error(w, "load credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if credsExist && encCreds != "" {
			credentials, err = crypto.DecryptIfNotEmpty(masterKey, encCreds)
			if err != nil {
				http.Error(w, "decrypt credentials: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		result := verifyDNSCredentials(ctx, provider, credentials)
		writeJSON(w, http.StatusOK, result)
	}
}

// verifyDNSCredentials dispatches to the correct provider ping and returns a result.
func verifyDNSCredentials(ctx context.Context, provider, credentials string) DNSVerifyResponse {
	switch strings.ToLower(provider) {
	case "cloudflare":
		return verifyCloudflare(ctx, credentials)
	case "hetzner":
		return verifyHetzner(ctx, credentials)
	case "digitalocean":
		return verifyDigitalOcean(ctx, credentials)
	case "linode":
		return verifyLinode(ctx, credentials)
	case "vultr":
		return verifyVultr(ctx, credentials)
	case "dnsimple":
		return verifyDNSimple(ctx, credentials)
	case "gandi":
		return verifyGandi(ctx, credentials)
	case "porkbun":
		return verifyPorkbun(ctx, credentials)
	default:
		return DNSVerifyResponse{
			Valid:     false,
			Supported: false,
			Message:   fmt.Sprintf("automatic verification is not supported for provider %q", provider),
		}
	}
}

// httpClient is shared across all pings with a conservative timeout.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// bearerPing performs GET url with "Authorization: Bearer <token>" and returns
// success when the response status is 2xx.
func bearerPing(ctx context.Context, url, token string) DNSVerifyResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return DNSVerifyResponse{Valid: false, Supported: true, Message: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	return evalResponse(httpClient.Do(req))
}

// headerPing performs GET url with a custom header name/value pair.
func headerPing(ctx context.Context, url, headerName, headerValue string) DNSVerifyResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return DNSVerifyResponse{Valid: false, Supported: true, Message: err.Error()}
	}
	req.Header.Set(headerName, strings.TrimSpace(headerValue))
	return evalResponse(httpClient.Do(req))
}

// evalResponse converts an HTTP response into a DNSVerifyResponse.
func evalResponse(resp *http.Response, err error) DNSVerifyResponse {
	if err != nil {
		return DNSVerifyResponse{Valid: false, Supported: true, Message: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return DNSVerifyResponse{Valid: true, Supported: true, Message: "OK"}
	}
	return DNSVerifyResponse{
		Valid:     false,
		Supported: true,
		Message:   fmt.Sprintf("provider returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),
	}
}

// ── provider implementations ─────────────────────────────────────────────────

func verifyCloudflare(ctx context.Context, token string) DNSVerifyResponse {
	return bearerPing(ctx, "https://api.cloudflare.com/client/v4/user/tokens/verify", token)
}

func verifyHetzner(ctx context.Context, token string) DNSVerifyResponse {
	return headerPing(ctx, "https://dns.hetzner.com/api/v1/zones", "Auth-API-Token", token)
}

func verifyDigitalOcean(ctx context.Context, token string) DNSVerifyResponse {
	return bearerPing(ctx, "https://api.digitalocean.com/v2/account", token)
}

func verifyLinode(ctx context.Context, token string) DNSVerifyResponse {
	return bearerPing(ctx, "https://api.linode.com/v4/profile", token)
}

func verifyVultr(ctx context.Context, token string) DNSVerifyResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.vultr.com/v2/account", nil)
	if err != nil {
		return DNSVerifyResponse{Valid: false, Supported: true, Message: err.Error()}
	}
	req.Header.Set("Authorization", "Token "+strings.TrimSpace(token))
	return evalResponse(httpClient.Do(req))
}

func verifyDNSimple(ctx context.Context, token string) DNSVerifyResponse {
	return bearerPing(ctx, "https://api.dnsimple.com/v2/whoami", token)
}

func verifyGandi(ctx context.Context, token string) DNSVerifyResponse {
	return headerPing(ctx, "https://api.gandi.net/v5/livedns/domains", "Authorization", "Apikey "+strings.TrimSpace(token))
}

// verifyPorkbun expects credentials as JSON: {"apikey":"...","secretapikey":"..."}
func verifyPorkbun(ctx context.Context, credentials string) DNSVerifyResponse {
	// Try to parse as JSON first; fall back to treating the whole string as apikey.
	var creds struct {
		APIKey    string `json:"apikey"`
		SecretKey string `json:"secretapikey"`
	}
	if err := json.Unmarshal([]byte(credentials), &creds); err != nil || creds.APIKey == "" {
		return DNSVerifyResponse{
			Valid:     false,
			Supported: true,
			Message:   `credentials must be JSON: {"apikey":"...","secretapikey":"..."}`,
		}
	}
	body, _ := json.Marshal(creds)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.porkbun.com/api/json/v3/ping",
		strings.NewReader(string(body)))
	if err != nil {
		return DNSVerifyResponse{Valid: false, Supported: true, Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	return evalResponse(httpClient.Do(req))
}
