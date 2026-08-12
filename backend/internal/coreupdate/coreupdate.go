// Package coreupdate checks GitHub for a newer modulab-core release than the
// one currently running, on an admin-configurable weekday+time schedule
// (rather than a fixed interval, like store.RunSync's registry sync), and
// notifies every connected admin session over SSE the first time a
// new version is seen.
//
// Kept separate from internal/store (which already has FetchLatestRelease,
// reused here) because this package additionally owns Core's own update
// schedule/notification concerns - store deliberately stays generic
// "fetch a GitHub repo's latest release", with no opinion on when to call it
// or what to do with the result, the same separation modules.RunUpdateCheckOnce
// already has relative to store for community modules.
package coreupdate

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/store"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"github.com/modulab-project/modulab-core/backend/internal/version"
)

// coreRepoURL is modulab-core's own GitHub repo - the same one
// store.FetchLatestRelease is already pointed at from systemInfoHandler
// before this package existed.
const coreRepoURL = "https://github.com/modulab-project/modulab-core"

// tickInterval is how often the scheduler re-evaluates the configured
// weekday+time against the wall clock. Matches modules.jobTickInterval's
// reasoning exactly: the schedule is only ever evaluated at minute
// granularity (see CheckTime/defaultCheckTime), so there is no point
// ticking faster than once a minute.
const tickInterval = time.Minute

// defaultCheckWeekdaysRaw / defaultCheckTimeRaw are CheckWeekdaysRaw/
// CheckTimeRaw's fallbacks: every day, 03:00 - a quiet, low-traffic time
// that keeps day-one behaviour close to "checks daily" rather than
// silently doing nothing until an admin visits the settings page.
const (
	defaultCheckWeekdaysRaw = "0,1,2,3,4,5,6"
	defaultCheckTimeRaw     = "03:00"
)

// SettingKeyCheckWeekdays/SettingKeyCheckTime name the core_settings keys
// CheckWeekdaysRaw/CheckTimeRaw below read. Exported so adminapi.
// AdminLimitsHandler's PATCH handler writes through these instead of a
// second, independently-hardcoded string literal - found 2026-07-27 as the
// same "two copies, one of which can drift" pattern as the
// __Host-modulab_session cookie-name bug.
const (
	SettingKeyCheckWeekdays = "core_update_check_weekdays"
	SettingKeyCheckTime     = "core_update_check_time"
)

// CheckWeekdaysRaw reads the raw core_settings value for
// "core_update_check_weekdays" (a comma-separated list of time.Weekday
// integers, 0=Sunday..6=Saturday - the same convention modules/jobs.go's
// cronMatchesMinute already uses for its weekday field). Returns the
// default (every day) if unset or invalid; validation of an admin-supplied
// value happens once, at PATCH time (see adminapi.AdminLimitsHandler), so a
// value that reaches core_settings at all is already known-good - this
// fallback exists for "never configured yet", not for tolerating bad input.
func CheckWeekdaysRaw(ctx context.Context, pool *db.Pool) string {
	val, ok, err := pool.GetSetting(ctx, SettingKeyCheckWeekdays)
	if err != nil || !ok || val == "" {
		return defaultCheckWeekdaysRaw
	}
	if _, err := ParseWeekdays(val); err != nil {
		return defaultCheckWeekdaysRaw
	}
	return val
}

// CheckTimeRaw reads the raw core_settings value for
// "core_update_check_time" ("HH:MM", 24h). Same fallback reasoning as
// CheckWeekdaysRaw above.
func CheckTimeRaw(ctx context.Context, pool *db.Pool) string {
	val, ok, err := pool.GetSetting(ctx, SettingKeyCheckTime)
	if err != nil || !ok || val == "" {
		return defaultCheckTimeRaw
	}
	if _, _, err := ParseTime(val); err != nil {
		return defaultCheckTimeRaw
	}
	return val
}

// ParseWeekdays parses a comma-separated list of weekday integers (0-6, Sun-Sat)
// into a set. Returns an error on anything else (empty entries, out-of-range
// numbers, non-numeric tokens) so the PATCH handler can reject a malformed
// value outright instead of silently storing something the scheduler would
// later fail to parse (and fall back on default for) anyway.
func ParseWeekdays(raw string) (map[time.Weekday]bool, error) {
	parts := strings.Split(raw, ",")
	out := make(map[time.Weekday]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("coreupdate: empty weekday entry in %q", raw)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 6 {
			return nil, fmt.Errorf("coreupdate: invalid weekday %q (must be 0-6)", p)
		}
		out[time.Weekday(n)] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("coreupdate: at least one weekday must be selected")
	}
	return out, nil
}

// ParseTime parses "HH:MM" (24h) into hour/minute. Deliberately not using
// time.Parse("15:04", ...) directly for the error message's sake - the
// admin-facing validation error (AdminLimitsHandler) is clearer as "must be
// HH:MM" than whatever time.Parse's own message happens to say.
func ParseTime(raw string) (hour, minute int, err error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("coreupdate: invalid time %q (must be HH:MM)", raw)
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("coreupdate: invalid time %q (must be HH:MM, 00:00-23:59)", raw)
	}
	return h, m, nil
}

// CheckResult is CheckNow's outcome, also the JSON body of the manual
// "check now" endpoint (POST /v1/admin/system/core-update-check).
type CheckResult struct {
	LatestVersion   string `json:"latest_core_version,omitempty"`
	UpdateAvailable bool   `json:"core_update_available"`
}

// CachedResult reads back the last CheckNow outcome from core_settings,
// without calling GitHub again - used by systemInfoHandler so opening
// /admin/system/info does not itself trigger a live GitHub API call on
// every page load (that used to be the case before this package existed;
// GitHub's unauthenticated rate limit is 60 requests/hour per IP, cheap to
// exhaust by just refreshing the page a few dozen times). The scheduler
// (RunScheduler below) and the manual check endpoint are the only two
// things that actually call GitHub; everything else reads this cache.
func CachedResult(ctx context.Context, pool *db.Pool) CheckResult {
	latest, _, _ := pool.GetSetting(ctx, "core_latest_known_version")
	if latest == "" {
		return CheckResult{}
	}
	return CheckResult{LatestVersion: latest, UpdateAvailable: isNewerVersion(latest, version.Version)}
}

// isNewerVersion reports whether latest is a strictly greater semantic
// version than current ("X.Y.Z", no leading "v" - see version.Version's doc
// comment). Malformed segments compare as 0, so a garbled cached value never
// panics, it just fails the "is newer" check.
//
// Added 2026-08-03 to fix a false-positive "update available" badge: both
// CachedResult and CheckNow used to compare with a plain latest !=
// version.Version. core_latest_known_version is only refreshed by the daily
// scheduler or a manual "check now" (see CachedResult's doc comment above),
// so right after an admin manually installs a new release and restarts, the
// cache can still hold an *older* version than the one now running (last
// checked before the release the admin just installed). != flagged that as
// "update available" and displayed the stale, older cached version as the
// suggested update - exactly backwards. Only a real "latest > current" now
// counts.
func isNewerVersion(latest, current string) bool {
	l := parseVersionParts(latest)
	c := parseVersionParts(current)
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// parseVersionParts splits "X.Y.Z" into its three numeric components.
// Missing or non-numeric segments become 0 rather than erroring - callers
// only use this for ordering, not validation.
func parseVersionParts(v string) [3]int {
	var out [3]int
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil {
			n = 0
		}
		out[i] = n
	}
	return out
}

// CheckNow performs one live GitHub lookup, caches the result for
// CachedResult, and - the first time a given newer version is seen -
// publishes a "core.update_available" event to notify.AdminChannel so
// every currently-connected admin session's SSE stream picks it up live
// (auth/events.go), the same delivery path modules.RunUpdateCheckOnce
// already uses for "module.updates_available". Before 2026-07-29's
// role-model change this was scoped to a narrower SuperAdminChannel,
// deliberately excluding org-admin sessions; both the separate channel and
// the org-admin tier are gone now, so this reuses the one admin channel
// like everything else.
//
// The "first time seen" dedup (core_update_last_notified_version) matters
// because this runs on every scheduled tick that happens to land after a
// release: without it, an admin who is online across several ticks after a
// new release would get the same toast repeated on every tick until they
// upgrade, not just once.
func CheckNow(ctx context.Context, pool *db.Pool, vk *valkey.Client) (CheckResult, error) {
	latest, err := store.FetchLatestRelease(ctx, pool, coreRepoURL, "")
	if err != nil {
		return CheckResult{}, fmt.Errorf("coreupdate: check now: %w", err)
	}
	if latest == "" {
		// No releases found (or a soft-failed lookup - see
		// store.FetchLatestRelease's doc comment on 404 handling). Leave
		// whatever was cached before alone rather than overwriting it with
		// "no update known" on what might just be a transient GitHub hiccup.
		return CachedResult(ctx, pool), nil
	}
	normalized := strings.TrimPrefix(strings.TrimSpace(latest), "v")

	if err := pool.SetSetting(ctx, "core_latest_known_version", normalized); err != nil {
		log.Printf("coreupdate: cache latest version: %v", err)
	}
	if err := pool.SetSetting(ctx, "core_last_checked_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("coreupdate: cache last-checked time: %v", err)
	}

	result := CheckResult{LatestVersion: normalized, UpdateAvailable: isNewerVersion(normalized, version.Version)}

	if result.UpdateAvailable && vk != nil {
		lastNotified, _, _ := pool.GetSetting(ctx, "core_update_last_notified_version")
		if lastNotified != normalized {
			ev := notify.Event{Type: "core.update_available", Data: map[string]any{"version": normalized}}
			if err := notify.Publish(ctx, vk, notify.AdminChannel(), ev); err != nil {
				log.Printf("coreupdate: publish event: %v", err)
			} else if err := pool.SetSetting(ctx, "core_update_last_notified_version", normalized); err != nil {
				log.Printf("coreupdate: record last-notified version: %v", err)
			}
		}
	}

	return result, nil
}

// RunScheduler is the long-running background goroutine driving the
// weekday+time-scheduled check. Ticks every minute (tickInterval) and fires
// CheckNow at most once per calendar day, the moment the wall clock first
// matches the configured weekday+time - not a fixed-interval timer like
// store.RunSync, since the schedule here is "at HH:MM on these weekdays",
// which a re-armed interval can't express directly. Re-reads
// CheckWeekdaysRaw/CheckTimeRaw fresh on every tick (not cached at
// goroutine start) so an admin's settings change takes effect on the very
// next tick, same reasoning as store.RunSync's interval re-read.
//
// Does not run once immediately on startup (unlike store.RunSync): a
// version check is a "did anything change since I last looked" question,
// not something that needs to be warm before an admin opens a page -
// systemInfoHandler already has CachedResult (last known value, possibly
// from before a restart) to show in the meantime. Started with
// `go coreupdate.RunScheduler(ctx, pool, vk)` from main.go.
//
// Evaluated against setup.SystemTimezoneLocation, not the container's own
// wall clock (fixed 2026-08-12, same bug and same fix as internal/geoip.
// RunScheduler's own): the admin-facing "HH:MM" field is a plain
// <input type="time"> the browser fills in the admin's local time, but every
// ModuLab container this project has seen runs its own clock in UTC, with
// nothing in the UI to hint the two differ. Re-read every tick, same
// reasoning as CheckWeekdaysRaw/CheckTimeRaw below, so a timezone change on
// admin/system/general also takes effect on the very next tick.
func RunScheduler(ctx context.Context, pool *db.Pool, vk *valkey.Client) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	var lastRunDate string // "2026-07-21" form; empty until the first run this process lifetime

	for {
		select {
		case <-ticker.C:
			now := time.Now().In(setup.SystemTimezoneLocation(ctx, pool))
			today := now.Format("2006-01-02")
			if today == lastRunDate {
				continue // already ran today - a missed/duplicate tick within the same minute is a no-op, not a re-run
			}

			weekdays, err := ParseWeekdays(CheckWeekdaysRaw(ctx, pool))
			if err != nil {
				// Unreachable in practice - CheckWeekdaysRaw only ever
				// returns a value it already validated or the known-good
				// default - but fail closed (skip this tick) rather than
				// panic if that invariant is ever broken.
				log.Printf("coreupdate: scheduler: %v", err)
				continue
			}
			if !weekdays[now.Weekday()] {
				continue
			}
			hour, minute, err := ParseTime(CheckTimeRaw(ctx, pool))
			if err != nil {
				log.Printf("coreupdate: scheduler: %v", err)
				continue
			}
			if now.Hour() != hour || now.Minute() != minute {
				continue
			}

			lastRunDate = today
			if _, err := CheckNow(ctx, pool, vk); err != nil {
				log.Printf("coreupdate: scheduled check: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}
