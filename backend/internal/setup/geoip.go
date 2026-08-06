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
	"time"

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
	// GeoIPLastCheckAtSettingKey marks when internal/geoip last actually
	// attempted a download - unlike GeoIPLastUpdateAtSettingKey (success
	// only), this is written on every attempt regardless of outcome. Used
	// exclusively to compute GeoIPUpdateTimer's "next check in ..."
	// countdown, which must track the real schedule (RunScheduler ticks
	// every TickInterval no matter whether the previous attempt failed),
	// not silently freeze at the last success.
	GeoIPLastCheckAtSettingKey = "geoip_last_check_at"
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
	// CityFile/ASNFile report each edition's .mmdb file as it currently
	// sits on disk, independent of Configured - GeoIPDeleteHandler
	// deliberately leaves already-downloaded files in place (see its own
	// doc comment), so an admin who cleared credentials can still see a
	// stale-but-present database here rather than the page going blank.
	// Populated by the fileStatus callback GeoIPStatusHandler is given
	// (internal/geoip.Status, wired up in cmd/core/main.go) - this package
	// cannot import internal/geoip directly without a circular import (see
	// this file's top-of-file doc comment on GeoIPConfigureHandler's
	// triggerDownload for the exact same reasoning).
	CityFile GeoIPFileInfo `json:"city_file"`
	ASNFile  GeoIPFileInfo `json:"asn_file"`
	// UpdateTimer reports the background refresh schedule - same JSON shape
	// as adminapi/main.go's systemInfoTimer (last_run_at/next_run_at/
	// interval_seconds) on purpose, so the frontend's existing SystemInfoTimer
	// type and TimerCard-style rendering apply here unmodified. Populated
	// unconditionally, even when Configured is false, so the admin page can
	// still show the configured interval (and "not run yet") rather than the
	// whole card disappearing.
	UpdateTimer GeoIPUpdateTimer `json:"update_timer"`
}

// GeoIPUpdateTimer mirrors cmd/core/main.go's systemInfoTimer shape exactly
// (same field names/JSON tags) - duplicated rather than shared because
// systemInfoTimer lives in package main, which nothing outside cmd/core can
// import.
type GeoIPUpdateTimer struct {
	LastRunAt       *string `json:"last_run_at,omitempty"`
	NextRunAt       *string `json:"next_run_at,omitempty"`
	IntervalSeconds int64   `json:"interval_seconds"`
}

// GeoIPFileInfo describes one edition's .mmdb file on disk.
type GeoIPFileInfo struct {
	Exists bool `json:"exists"`
	// SizeBytes/ModifiedAt/BuildDate are only meaningful (and only
	// populated) when Exists is true. BuildDate may still be empty even
	// then - it comes from parsing the file's own embedded metadata
	// (internal/geoip.FileInfo.BuildDate), which fails open on a corrupt or
	// unreadable file rather than erroring the whole status response.
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"` // RFC3339
	// BuildDate is MaxMind's own edition build timestamp (when MaxMind
	// itself generated this database), not when Core downloaded it -
	// see internal/geoip.FileInfo.BuildDate's doc comment for why both are
	// useful.
	BuildDate string `json:"build_date,omitempty"` // RFC3339
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

// resolveUpdateTimer builds a GeoIPUpdateTimer from GeoIPLastCheckAtSettingKey
// and the caller-supplied interval - called unconditionally (even when GeoIP
// is not configured) so the admin page can still show what interval would
// apply, and "not run yet" rather than the card disappearing. checkIntervalSeconds
// comes from internal/geoip.TickInterval via cmd/core/main.go, since this
// package cannot import internal/geoip directly (see this file's top-of-file
// doc comment).
func resolveUpdateTimer(ctx context.Context, pool *db.Pool, checkIntervalSeconds int64) GeoIPUpdateTimer {
	timer := GeoIPUpdateTimer{IntervalSeconds: checkIntervalSeconds}
	lastCheckAt, exists, err := pool.GetSetting(ctx, GeoIPLastCheckAtSettingKey)
	if err != nil || !exists || lastCheckAt == "" {
		return timer
	}
	lastCheck, err := time.Parse(time.RFC3339, lastCheckAt)
	if err != nil {
		return timer
	}
	nextCheck := lastCheck.Add(time.Duration(checkIntervalSeconds) * time.Second)
	lastStr := lastCheck.UTC().Format(time.RFC3339)
	nextStr := nextCheck.UTC().Format(time.RFC3339)
	timer.LastRunAt = &lastStr
	timer.NextRunAt = &nextStr
	return timer
}

// GeoIPStatusHandler reports whether GeoIP has been configured, and if so,
// every field except the license key. masterKey is required to decrypt the
// account ID. fileStatus reports each edition's on-disk .mmdb file (see
// internal/geoip.Status, wired up by cmd/core/main.go) - called
// unconditionally, even when GeoIP is not (or no longer) configured, since
// GeoIPDeleteHandler leaves already-downloaded files in place.
// checkIntervalSeconds is internal/geoip.TickInterval in seconds - see
// resolveUpdateTimer's doc comment for why it has to be passed in rather
// than read directly.
func GeoIPStatusHandler(pool *db.Pool, masterKey string, fileStatus func() (city, asn GeoIPFileInfo), checkIntervalSeconds int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cityFile, asnFile := fileStatus()
		updateTimer := resolveUpdateTimer(ctx, pool, checkIntervalSeconds)

		encAccountID, exists, err := pool.GetSetting(ctx, geoIPAccountIDSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !exists {
			httperr.JSON(w, http.StatusOK, GeoIPStatusResponse{Configured: false, CityFile: cityFile, ASNFile: asnFile, UpdateTimer: updateTimer})
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
			CityFile:        cityFile,
			ASNFile:         asnFile,
			UpdateTimer:     updateTimer,
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
// not called. fileStatus is read AFTER triggerDownload returns, so the
// response already reflects whatever the just-triggered download produced
// (or didn't, on failure) rather than requiring a second round-trip to
// GET .../status to see it. checkIntervalSeconds is passed straight through
// to resolveUpdateTimer - see GeoIPStatusHandler's doc comment.
func GeoIPConfigureHandler(pool *db.Pool, masterKey string, triggerDownload func(), fileStatus func() (city, asn GeoIPFileInfo), checkIntervalSeconds int64) http.HandlerFunc {
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
		var cityFile, asnFile GeoIPFileInfo
		if fileStatus != nil {
			cityFile, asnFile = fileStatus()
		}
		httperr.JSON(w, http.StatusOK, GeoIPStatusResponse{
			Configured:      true,
			AccountID:       req.AccountID,
			LastUpdateAt:    lastUpdateAt,
			LastUpdateError: lastUpdateError,
			CityFile:        cityFile,
			ASNFile:         asnFile,
			UpdateTimer:     resolveUpdateTimer(ctx, pool, checkIntervalSeconds),
		})
	}
}

// GeoIPDeleteHandler clears the GeoIP configuration entirely (all five
// settings keys, including the last-update/last-check bookkeeping), returning the
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
			GeoIPLastCheckAtSettingKey,
		} {
			if err := pool.DeleteSetting(ctx, key); err != nil {
				httperr.Internal(w, err)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
