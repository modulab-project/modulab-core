// This file implements the instance-wide system_timezone setting, backing
// GET/PATCH /v1/admin/system/general (adminapi.AdminGeneralHandler)
// alongside mail.SettingKeySystemLanguage/SettingKeyInstanceName - see that
// handler's own doc comment for why cross-cutting, non-secret config lives
// on that page rather than its own.
//
// Added 2026-08-12 to fix a real scheduling bug: internal/geoip.RunScheduler
// and internal/coreupdate.RunScheduler both compare an admin-entered "HH:MM"
// (typed into a plain <input type="time">, which the browser renders and
// submits in the admin's OWN local time) against time.Now() - the
// container's wall clock, which in every ModuLab deployment this project has
// seen is UTC. An admin in, say, Europe/Berlin (UTC+1 in winter, UTC+2 in
// summer) who types "03:00" expecting "3 AM my time" actually gets a
// download at 3 AM UTC = 4 or 5 AM their time, with no indication anywhere
// in the UI that the two clocks differ. Per-browser local<->UTC conversion
// at the API boundary was considered and rejected: it would silently break
// the moment two admins in different timezones share one instance, and it
// gives the admin no way to make the schedule match a *specific* zone (e.g.
// "always 3 AM in the datacenter's timezone, regardless of who edits the
// setting"). A single, explicit, instance-wide setting - the same shape as
// SystemLanguage/InstanceName above it on the same page - fixes both: one
// unambiguous zone every scheduler agrees on, editable by any admin, visible
// to all of them.
package setup

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const (
	// SystemTimezoneSettingKey names the core_settings key
	// SystemTimezoneRaw/SystemTimezoneLocation read and
	// adminapi.AdminGeneralHandler's PATCH branch writes - an IANA Time Zone
	// Database name ("Europe/Berlin", "America/New_York", "UTC", ...), never
	// a raw UTC offset: offsets alone can't express DST transitions, which
	// is exactly the kind of silent drift this setting exists to eliminate.
	SystemTimezoneSettingKey = "system_timezone"

	// DefaultSystemTimezone is SystemTimezoneRaw's fallback for a fresh
	// install (or any instance that has never visited admin/system/general).
	// UTC, not the container's local zone: it's the one zone every existing
	// ModuLab deployment's wall clock already runs on (see this file's
	// top-of-file doc comment), so a never-configured instance keeps
	// exactly the scheduling behavior it had before this setting existed -
	// no silent behavior change on upgrade.
	DefaultSystemTimezone = "UTC"
)

// ParseSystemTimezone validates raw as an IANA Time Zone Database name and
// returns the resolved *time.Location. Requires the OS's tzdata package to
// be installed wherever this runs (see the Dockerfile's final stage's
// `apt-get install` list) - debian:bookworm-slim does not include it by
// default, and without it time.LoadLocation would fail closed to UTC for
// every zone name except "UTC" and "Local" itself.
func ParseSystemTimezone(raw string) (*time.Location, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("setup: system timezone must not be empty")
	}
	loc, err := time.LoadLocation(raw)
	if err != nil {
		return nil, fmt.Errorf("setup: invalid IANA timezone %q: %w", raw, err)
	}
	return loc, nil
}

// SystemTimezoneRaw reads the raw core_settings value for
// SystemTimezoneSettingKey. Returns DefaultSystemTimezone if unset or
// invalid - validation of an admin-supplied value happens once, at PATCH
// time (adminapi.AdminGeneralHandler), so a value that reaches
// core_settings at all is already known-good; this fallback exists for
// "never configured yet" or a row corrupted outside the API, not for
// tolerating routinely-bad input.
func SystemTimezoneRaw(ctx context.Context, pool *db.Pool) string {
	val, ok, err := pool.GetSetting(ctx, SystemTimezoneSettingKey)
	if err != nil || !ok || val == "" {
		return DefaultSystemTimezone
	}
	if _, err := ParseSystemTimezone(val); err != nil {
		return DefaultSystemTimezone
	}
	return val
}

// SystemTimezoneLocation is SystemTimezoneRaw resolved to a *time.Location -
// what internal/geoip.RunScheduler, internal/setup's own resolveUpdateTimer,
// and internal/coreupdate.RunScheduler actually need to evaluate a
// configured "HH:MM" against the admin's intended wall clock instead of the
// container's. Re-resolved on every call rather than cached (same choice
// mail.CurrentBranding and ResolveSMTPConfig already make), so a timezone
// change saved on the settings page takes effect on the very next scheduler
// tick, no Core restart required. Fails open to time.UTC - which is also
// DefaultSystemTimezone's resolved value - rather than erroring, since every
// caller here is a background loop that must keep ticking even if
// core_settings is briefly unreadable.
func SystemTimezoneLocation(ctx context.Context, pool *db.Pool) *time.Location {
	loc, err := ParseSystemTimezone(SystemTimezoneRaw(ctx, pool))
	if err != nil {
		return time.UTC
	}
	return loc
}
