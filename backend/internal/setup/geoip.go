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
	"strconv"
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
	// only), this is written on every attempt regardless of outcome. Surfaced
	// as GeoIPUpdateTimer.LastRunAt so the admin page can show "last checked
	// at ..." even after a run of failures, not silently freeze at the last
	// success - NextRunAt itself no longer derives from this (see
	// resolveUpdateTimer's doc comment), only LastRunAt does.
	GeoIPLastCheckAtSettingKey = "geoip_last_check_at"
	// GeoIPCheckTimeSettingKey names the core_settings key
	// internal/geoip.CheckTimeRaw reads for the fixed daily time-of-day
	// ("HH:MM", 24h) RunScheduler downloads at - exported (not internal/
	// geoip's own unexported constant) so GeoIPConfigureHandler below can
	// write it directly, same direction as the three keys above. Replaces
	// the former interval-hours field entirely (2026-08-09): MaxMind only
	// republishes GeoLite2 weekly, so "check once a day, at a specific
	// clock time" is both easier for an admin to reason about than a raw
	// hour count and mirrors admin/system/limits' own
	// core_update_check_time field (see coreupdate.SettingKeyCheckTime),
	// which this directly follows the shape of. Deliberately NOT cleared by
	// GeoIPDeleteHandler: it is a scheduling preference, not a credential,
	// and an admin re-adding GeoIP later almost certainly wants whatever
	// check time they'd already picked to still apply.
	GeoIPCheckTimeSettingKey = "geoip_check_time"
)

// ParseGeoIPCheckTime parses "HH:MM" (24h) into hour/minute. Deliberately a
// local copy of coreupdate.ParseTime's exact logic rather than an import of
// it: this package already avoids importing internal/geoip to sidestep a
// circular import (see this file's top-of-file doc comment), and reaching
// into internal/coreupdate - a feature package with nothing to do with
// GeoIP - just to share one tiny string parser would trade a real circular-
// import problem for an equally arbitrary cross-feature coupling.
func ParseGeoIPCheckTime(raw string) (hour, minute int, err error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("setup: invalid geoip check time %q (must be HH:MM)", raw)
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("setup: invalid geoip check time %q (must be HH:MM, 00:00-23:59)", raw)
	}
	return h, m, nil
}

// GeoIPConfigRequest is the body of POST /v1/admin/geoip/configure.
type GeoIPConfigRequest struct {
	AccountID  string `json:"account_id"`
	LicenseKey string `json:"license_key"`
	// CheckTime is optional - "" (indistinguishable from "field omitted" in
	// JSON) means "leave the current check time unchanged" rather than
	// "clear it" (see GeoIPConfigureHandler's validation). The frontend
	// always sends the currently effective value (from the last GET
	// .../status response) back here, so in practice this only actually
	// changes when the admin edits the field. "HH:MM", 24h - validated via
	// ParseGeoIPCheckTime.
	CheckTime string `json:"check_time,omitempty"`
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
	// UpdateTimer reports the background refresh schedule - see
	// GeoIPUpdateTimer's own doc comment for its shape. Populated
	// unconditionally, even when Configured is false, so the admin page can
	// still show the configured check time (and "not run yet") rather than
	// the whole card disappearing.
	UpdateTimer GeoIPUpdateTimer `json:"update_timer"`
}

// GeoIPUpdateTimer reports the GeoIP background refresh schedule. Unlike
// cmd/core/main.go's systemInfoTimer/adminapi's other timer shapes (last_run_at/
// next_run_at/interval_seconds), this carries CheckTime instead of an
// interval: since 2026-08-09 the schedule is "once a day, at a fixed clock
// time" (see GeoIPCheckTimeSettingKey's doc comment), not a re-arming
// interval, so NextRunAt is computed from CheckTime and the current wall
// clock (see resolveUpdateTimer) rather than LastRunAt+interval.
type GeoIPUpdateTimer struct {
	LastRunAt *string `json:"last_run_at,omitempty"`
	NextRunAt *string `json:"next_run_at,omitempty"`
	// CheckTime is the currently effective "HH:MM" (24h) daily check time.
	CheckTime string `json:"check_time"`
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
// and the caller-supplied check time - called unconditionally (even when
// GeoIP is not configured) so the admin page can still show what time would
// apply, and "not run yet" rather than the card disappearing. checkTimeRaw
// is a callback (not a plain value) so it can read internal/geoip.
// CheckTimeRaw fresh on every call - this package cannot import internal/
// geoip directly (see this file's top-of-file doc comment), and the check
// time itself is admin-configurable, so a cached/stale value would show the
// wrong countdown right after a change.
//
// NextRunAt is derived purely from the current wall clock and the configured
// HH:MM (today's occurrence if it hasn't passed yet, otherwise tomorrow's) -
// unlike the former interval-based calculation, it does NOT depend on
// LastRunAt at all, since the schedule is now "every day at this clock
// time" rather than "N seconds after the last attempt".
func resolveUpdateTimer(ctx context.Context, pool *db.Pool, checkTimeRaw func(context.Context) string) GeoIPUpdateTimer {
	raw := checkTimeRaw(ctx)
	timer := GeoIPUpdateTimer{CheckTime: raw}

	if lastCheckAt, exists, err := pool.GetSetting(ctx, GeoIPLastCheckAtSettingKey); err == nil && exists && lastCheckAt != "" {
		if lastCheck, err := time.Parse(time.RFC3339, lastCheckAt); err == nil {
			lastStr := lastCheck.UTC().Format(time.RFC3339)
			timer.LastRunAt = &lastStr
		}
	}

	hour, minute, err := ParseGeoIPCheckTime(raw)
	if err != nil {
		// Unreachable in practice - checkTimeRaw only ever returns a value
		// it already validated or the known-good default - but fail closed
		// (no NextRunAt) rather than panic if that invariant is ever broken.
		return timer
	}
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	nextStr := next.UTC().Format(time.RFC3339)
	timer.NextRunAt = &nextStr
	return timer
}

// GeoIPStatusHandler reports whether GeoIP has been configured, and if so,
// every field except the license key. masterKey is required to decrypt the
// account ID. fileStatus reports each edition's on-disk .mmdb file (see
// internal/geoip.Status, wired up by cmd/core/main.go) - called
// unconditionally, even when GeoIP is not (or no longer) configured, since
// GeoIPDeleteHandler leaves already-downloaded files in place.
// checkTimeRaw reads internal/geoip.CheckTimeRaw - see resolveUpdateTimer's
// doc comment for why it has to be a callback rather than a plain value
// passed in once.
func GeoIPStatusHandler(pool *db.Pool, masterKey string, fileStatus func() (city, asn GeoIPFileInfo), checkTimeRaw func(context.Context) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cityFile, asnFile := fileStatus()
		updateTimer := resolveUpdateTimer(ctx, pool, checkTimeRaw)

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
// GET .../status to see it. checkTimeRaw is passed straight through
// to resolveUpdateTimer - see GeoIPStatusHandler's doc comment.
func GeoIPConfigureHandler(pool *db.Pool, masterKey string, triggerDownload func(), fileStatus func() (city, asn GeoIPFileInfo), checkTimeRaw func(context.Context) string) http.HandlerFunc {
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
		// Only overwrite the check time when a non-empty value was
		// submitted - see GeoIPConfigRequest.CheckTime's doc comment on why
		// "" means "leave unchanged" rather than "invalid". Written
		// separately from `settings` above since it's plaintext, not an
		// encrypted credential. A malformed value IS rejected outright
		// (unlike the account ID/license key, which have no format to
		// validate beyond non-empty) so an admin typo never silently reaches
		// the scheduler.
		if req.CheckTime != "" {
			if _, _, err := ParseGeoIPCheckTime(req.CheckTime); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := pool.SetSetting(ctx, GeoIPCheckTimeSettingKey, req.CheckTime); err != nil {
				httperr.Internal(w, err)
				return
			}
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
			UpdateTimer:     resolveUpdateTimer(ctx, pool, checkTimeRaw),
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
