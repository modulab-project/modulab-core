// This file implements MaxMind GeoLite2 IP geolocation configuration,
// fully driven from the ongoing Admin Panel (not the Setup Wizard's fixed
// 6-step sequence, nor any .env/docker-secrets value) - same placement
// reasoning as smtp.go: a fresh install is perfectly usable with no
// geolocation at all (sessions simply show no city/region/ISP, same as
// Country already degrades to "" without Cloudflare in front), so this has
// no business gating first-run setup.
//
// Same encrypted-at-rest treatment as SMTP's host/username/password: both
// the MaxMind Account ID and License Key are credential-tier secrets (spec
// section 2.4's 🔴 Kritisch tier - they are, together, everything needed to
// pull data from a paid/rate-limited MaxMind account), so both go through
// crypto.Encrypt before ever reaching core_settings, never stored or
// returned in plaintext. The License Key is never returned by
// GeoIPStatusHandler at all, mirroring SMTP's password.
//
// The actual database download/refresh (internal/geoip) is a separate
// package so this one has no dependency on net/http/archive-tar/etc. -
// GeoIPConfigureHandler is handed a triggerDownload callback instead of
// importing internal/geoip directly, avoiding a circular import (internal/
// geoip needs ResolveGeoIPConfig from this package to know what to
// download).
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
)

const (
	geoIPAccountIDSettingKey  = "geoip_maxmind_account_id_enc"
	geoIPLicenseKeySettingKey = "geoip_maxmind_license_key_enc"

	// GeoIPLastUpdateAtSettingKey / GeoIPLastUpdateErrorSettingKey are
	// plaintext (a timestamp and a diagnostic error string carry no PII,
	// same 🟢 Unkritisch exemption smtp.go's port/encryption fields get) -
	// exported so internal/geoip's background downloader can write them
	// directly after each attempt without this package needing to expose a
	// setter function per field.
	GeoIPLastUpdateAtSettingKey    = "geoip_last_update_at"
	GeoIPLastUpdateErrorSettingKey = "geoip_last_update_error"
)

// GeoIPConfigRequest is the body of POST /v1/admin/geoip/configure.
type GeoIPConfigRequest struct {
	AccountID  string `json:"account_id"`
	LicenseKey string `json:"license_key"`
}

// GeoIPStatusResponse reports the non-secret half of the configuration.
// LicenseKey is never included, mirroring SMTPStatusResponse's treatment
// of the password. LastUpdateAt/LastUpdateError reflect the most recent
// attempt by internal/geoip's background downloader (or the immediate
// one-off triggered by GeoIPConfigureHandler), so the admin page can show
// "last refreshed: ..." or surface a download failure (e.g. bad
// credentials) without having to check server logs.
type GeoIPStatusResponse struct {
	Configured      bool   `json:"configured"`
	AccountID       string `json:"account_id,omitempty"`
	LastUpdateAt    string `json:"last_update_at,omitempty"`
	LastUpdateError string `json:"last_update_error,omitempty"`
}

// GeoIPRuntimeConfig is the fully resolved configuration internal/geoip's
// downloader needs to actually call MaxMind's download endpoint. Never
// serialized to an HTTP response - LicenseKey has already been decrypted,
// so callers must not log it.
type GeoIPRuntimeConfig struct {
	AccountID  string
	LicenseKey string
}

// GeoIPConfigured reports whether GeoIP has already been configured. Used
// by internal/geoip's background downloader to decide whether there is
// anything to do at all - an instance that never configured GeoIP simply
// skips every tick quietly, same as SMTPConfigured's role for mail.RunWorker.
func GeoIPConfigured(ctx context.Context, pool *db.Pool) (bool, error) {
	_, exists, err := pool.GetSetting(ctx, geoIPAccountIDSettingKey)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// ResolveGeoIPConfig returns the effective GeoIP configuration as
// persisted by /v1/admin/geoip/configure, with LicenseKey decrypted using
// masterKey. Re-resolved on every download attempt (not cached), so a
// credential change in the admin panel takes effect on the very next
// scheduled tick without a Core restart - same pattern as
// ResolveSMTPConfig.
func ResolveGeoIPConfig(ctx context.Context, pool *db.Pool, masterKey string) (GeoIPRuntimeConfig, error) {
	encAccountID, exists, err := pool.GetSetting(ctx, geoIPAccountIDSettingKey)
	if err != nil {
		return GeoIPRuntimeConfig{}, err
	}
	if !exists {
		return GeoIPRuntimeConfig{}, fmt.Errorf("setup: geoip has not been configured yet (call /v1/admin/geoip/configure first)")
	}
	accountID, err := crypto.DecryptIfNotEmpty(masterKey, encAccountID)
	if err != nil {
		return GeoIPRuntimeConfig{}, fmt.Errorf("setup: decrypt geoip_maxmind_account_id: %w", err)
	}
	encLicenseKey, _, err := pool.GetSetting(ctx, geoIPLicenseKeySettingKey)
	if err != nil {
		return GeoIPRuntimeConfig{}, err
	}
	licenseKey, err := crypto.DecryptIfNotEmpty(masterKey, encLicenseKey)
	if err != nil {
		return GeoIPRuntimeConfig{}, fmt.Errorf("setup: decrypt geoip_maxmind_license_key: %w", err)
	}
	return GeoIPRuntimeConfig{
		AccountID:  accountID,
		LicenseKey: licenseKey,
	}, nil
}

// GeoIPStatusHandler reports whether GeoIP has been configured, and if so,
// every field except the license key. masterKey is required to decrypt the
// account ID.
func GeoIPStatusHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		encAccountID, exists, err := pool.GetSetting(ctx, geoIPAccountIDSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !exists {
			httperr.JSON(w, http.StatusOK, GeoIPStatusResponse{Configured: false})
			return
		}
		accountID, err := crypto.DecryptIfNotEmpty(masterKey, encAccountID)
		if err != nil {
			httperr.Internal(w, fmt.Errorf("decrypt geoip_maxmind_account_id: %w", err))
			return
		}

		lastUpdateAt, _, err := pool.GetSetting(ctx, GeoIPLastUpdateAtSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		lastUpdateError, _, err := pool.GetSetting(ctx, GeoIPLastUpdateErrorSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}

		httperr.JSON(w, http.StatusOK, GeoIPStatusResponse{
			Configured:      true,
			AccountID:       accountID,
			LastUpdateAt:    lastUpdateAt,
			LastUpdateError: lastUpdateError,
		})
	}
}

// GeoIPConfigureHandler validates and persists the GeoIP configuration.
// masterKey must already be resolved (see ResolveMasterKey) - LicenseKey is
// encrypted with it before ever touching the database, unless empty (see
// GeoIPConfigRequest's "keep existing" semantics below).
//
// triggerDownload is called synchronously after a successful save, so an
// admin who just entered fresh credentials sees the databases appear
// without waiting for internal/geoip.RunScheduler's next daily tick. It is
// a plain func() (no error/status returned) so this package never needs to
// import internal/geoip directly - see this file's doc comment for why
// that would be circular. A nil triggerDownload (e.g. in a test) is simply
// not called.
func GeoIPConfigureHandler(pool *db.Pool, masterKey string, triggerDownload func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req GeoIPConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		req.AccountID = strings.TrimSpace(req.AccountID)
		req.LicenseKey = strings.TrimSpace(req.LicenseKey)

		if req.AccountID == "" {
			http.Error(w, "account_id is required", http.StatusBadRequest)
			return
		}

		encAccountID, err := crypto.Encrypt(masterKey, req.AccountID)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		ctx := r.Context()
		settings := map[string]string{
			geoIPAccountIDSettingKey: encAccountID,
		}
		// Only overwrite the stored license key when a new one was
		// submitted. An empty field means "keep the existing license key" -
		// identical to how SMTPConfigureHandler treats Password. An admin
		// who wants to rotate the key must re-enter it here; deleting and
		// re-adding the whole configuration is not required.
		if req.LicenseKey != "" {
			encLicenseKey, err := crypto.Encrypt(masterKey, req.LicenseKey)
			if err != nil {
				httperr.Internal(w, err)
				return
			}
			settings[geoIPLicenseKeySettingKey] = encLicenseKey
		}
		for key, value := range settings {
			if err := pool.SetSetting(ctx, key, value); err != nil {
				httperr.Internal(w, err)
				return
			}
		}

		if triggerDownload != nil {
			triggerDownload()
		}

		lastUpdateAt, _, _ := pool.GetSetting(ctx, GeoIPLastUpdateAtSettingKey)
		lastUpdateError, _, _ := pool.GetSetting(ctx, GeoIPLastUpdateErrorSettingKey)
		httperr.JSON(w, http.StatusOK, GeoIPStatusResponse{
			Configured:      true,
			AccountID:       req.AccountID,
			LastUpdateAt:    lastUpdateAt,
			LastUpdateError: lastUpdateError,
		})
	}
}

// GeoIPDeleteHandler clears the GeoIP configuration entirely (all four
// settings keys, including the last-update bookkeeping), returning the
// instance to "not configured" - the counterpart to GeoIPConfigureHandler.
// After this, GeoIPConfigured reports false again and ResolveGeoIPConfig
// fails the same "has not been configured yet" way it does on a fresh
// install, so internal/geoip's scheduler tick (already tolerant of "not
// configured") applies without any further changes there. The already
// downloaded .mmdb files on disk are deliberately left in place - deleting
// them would make internal/geoip.LookupCity/LookupASN immediately start
// failing for every session, which is a bigger behavior change than "stop
// refreshing" and not what an admin clearing credentials is asking for;
// they simply go stale until GeoIP is configured again.
func GeoIPDeleteHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		for _, key := range []string{
			geoIPAccountIDSettingKey,
			geoIPLicenseKeySettingKey,
			GeoIPLastUpdateAtSettingKey,
			GeoIPLastUpdateErrorSettingKey,
		} {
			if err := pool.DeleteSetting(ctx, key); err != nil {
				httperr.Internal(w, err)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
