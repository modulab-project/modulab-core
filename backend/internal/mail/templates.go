package mail

import "strings"

// ApprovedMessage, LockedMessage, UnlockedMessage, and
// PendingApprovalMessage build the email for spec section 3.5's
// user-facing account lifecycle events - an extension beyond the spec's
// own Mail-Queue table (which only routes System-Alert and critical
// audit-log entries to mail, both Super-Admin-only): SSE (internal/notify)
// only reaches someone who happens to be connected right now, so these
// give the same events a channel that still reaches them later.
// PendingApprovalMessage closes the gap the other three didn't:
// notify.AdminChannel() tells whichever admin is currently connected
// about a new signup, but until this was added, an admin who was not
// online at that exact moment had no way to find out short of opening
// /admin/users and checking - now every current admin also gets an email.
//
// Every function below takes a Branding (branding.go) as its last
// parameter and renders in b.Lang, falling back to English for any
// language locales/*.json has no file for (defensive only - b.Lang is
// already validated against supportedLangs by CurrentBranding, so this
// only matters if a caller ever constructs a Branding by hand). Every
// place the literal product name would otherwise appear uses
// b.InstanceName instead, so an operator who renamed their instance sees
// their own name throughout, not "ModuLab".
//
// Translated subject/body copy lives in locales/*.json (see locales.go for
// how it's loaded and rendered), not inline in this file - the same
// per-language-JSON-file approach the frontend already uses for its own
// UI strings (frontend/src/locales/*.json), now that locales.go's named
// "{{token}}" substitution removes the positional-%s-order risk that used
// to be the reason for keeping every language in one Go map literal here.
//
// All nine (Approved/Locked/Unlocked/Deleted/PendingApproval, plus the
// four session/anomaly mails further down) follow the same shape -
// greeting, one short explanation, optionally a link or details block, a
// closing line, a signature - so an admin's inbox reads as one coherent
// product rather than differently-worded one-liners.

// ApprovedMessage is sent once admin.ApproveUserHandler succeeds. name is
// the recipient's own display name (may be empty - see greeting above).
func ApprovedMessage(to, name, frontendBaseURL string, b Branding) Message {
	s := stringsFor(b.Lang).Approved
	vars := map[string]string{
		"instance":  b.InstanceName,
		"greeting":  greeting(name, b.Lang),
		"link":      frontendBaseURL,
		"signature": signature(b.InstanceName, b.Lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// LockedMessage is sent once admin.LockUserHandler succeeds. Deliberately
// carries no link back to the frontend - signing in again is exactly what
// this message needs to discourage, unlike the other four.
func LockedMessage(to, name string, b Branding) Message {
	s := stringsFor(b.Lang).Locked
	vars := map[string]string{
		"instance":  b.InstanceName,
		"greeting":  greeting(name, b.Lang),
		"signature": signature(b.InstanceName, b.Lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// UnlockedMessage is sent once admin.UnlockUserHandler succeeds.
func UnlockedMessage(to, name, frontendBaseURL string, b Branding) Message {
	s := stringsFor(b.Lang).Unlocked
	vars := map[string]string{
		"instance":  b.InstanceName,
		"greeting":  greeting(name, b.Lang),
		"link":      frontendBaseURL,
		"signature": signature(b.InstanceName, b.Lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// DeletedMessage is sent once a user's account is removed, either via
// admin.DeleteUserHandler or auth.DeleteSelfHandler (the latter for the
// self-service case, see handlers.go). Like LockedMessage, deliberately
// carries no link back to the frontend - signing in would just JIT-
// provision a brand-new pending row, not restore anything, so there is
// nothing useful to link to. Both call sites must capture to/name *before*
// the row is deleted (db.Pool.GetUser for the admin case, the caller's own
// already-loaded Session for the self-delete case) - there is no user row
// left to look the email up from afterward.
func DeletedMessage(to, name string, b Branding) Message {
	s := stringsFor(b.Lang).Deleted
	vars := map[string]string{
		"instance":  b.InstanceName,
		"greeting":  greeting(name, b.Lang),
		"signature": signature(b.InstanceName, b.Lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// PendingApprovalMessage is sent to every current admin
// (db.Pool.ListAdmins) once a brand-new pending signup is created -
// CallbackHandler's wasNew && !approved case in handlers.go, the same
// moment that publishes the "user.pending" SSE event. to/name identify
// the *admin* being written to (for the greeting); requesterName/
// requesterEmail identify the person waiting for approval. requesterName
// may be empty (same optionality as everywhere else a display name comes
// from the IdP) - rendered via notProvidedText rather than left blank.
func PendingApprovalMessage(to, name, frontendBaseURL, requesterName, requesterEmail string, b Branding) Message {
	displayRequesterName := strings.TrimSpace(requesterName)
	if displayRequesterName == "" {
		displayRequesterName = notProvidedText(b.Lang)
	}
	s := stringsFor(b.Lang).PendingApproval
	vars := map[string]string{
		"instance":        b.InstanceName,
		"greeting":        greeting(name, b.Lang),
		"requester_name":  displayRequesterName,
		"requester_email": requesterEmail,
		"link":            strings.TrimRight(frontendBaseURL, "/"),
		"signature":       signature(b.InstanceName, b.Lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// LoginMessage is sent on every successful login for a user who has
// notify_new_login enabled (db.NotificationPrefs, users.notify_new_login,
// default true) - unlike AnomalyMessage below, this is unconditional: no
// country/device comparison, just "you just signed in", the same category
// of mail Google/GitHub send on every new session by default. Users who
// find that too noisy (e.g. signing in from the same device daily) can turn
// it off from their Profile page without losing AnomalyMessage/
// NewDeviceMessage, which stay gated by their own separate toggles.
//
// country is despite its name a display-only location string, not
// necessarily a bare CF-IPCountry code any more: callers pass
// auth.mailLocation's result, which prepends internal/geoip's city lookup
// ("Frankfurt am Main, DE") when GeoIP is configured and has data for the
// login's IP, falling back to the plain country code otherwise. Never used
// for any comparison here - purely the "Location:" line's value.
func LoginMessage(to, name, ip, country, userAgent, frontendBaseURL string, b Branding) Message {
	lang := b.Lang
	if ip == "" {
		ip = unknownText(lang)
	}
	if country == "" {
		country = unknownText(lang)
	}
	if userAgent == "" {
		userAgent = unknownText(lang)
	}
	s := stringsFor(lang).Login
	vars := map[string]string{
		"instance":  b.InstanceName,
		"greeting":  greeting(name, lang),
		"location":  country,
		"ip":        ip,
		"device":    userAgent,
		"link":      strings.TrimRight(frontendBaseURL, "/"),
		"signature": signature(b.InstanceName, lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// NewDeviceMessage is AnomalyMessage's device-based counterpart: sent when
// auth.checkSessionDeviceAnomaly (session.go) sees an already-active
// session's request suddenly carry a different User-Agent than the one
// recorded for it - a change that country-based detection cannot catch
// (same country, different device/browser), and unlike a fresh login, one a
// legitimate user's own browser would never produce on its own mid-session.
// Gated by notify_new_device (db.NotificationPrefs), default true.
func NewDeviceMessage(to, name, ip, previousUserAgent, currentUserAgent, frontendBaseURL string, b Branding) Message {
	lang := b.Lang
	if ip == "" {
		ip = unknownText(lang)
	}
	s := stringsFor(lang).NewDevice
	vars := map[string]string{
		"instance":        b.InstanceName,
		"greeting":        greeting(name, lang),
		"previous_device": previousUserAgent,
		"current_device":  currentUserAgent,
		"ip":              ip,
		"link":            strings.TrimRight(frontendBaseURL, "/"),
		"signature":       signature(b.InstanceName, lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// SessionRevokedByAdminMessage is sent to a user whenever an admin ends one
// of their active sessions (auth.RevokeSessionByID, System Info page's
// per-row "end session" action) - never for RevokeOwnSessionByID (a user
// ending their own session from their own Profile page needs no mail
// telling them about the very thing they just clicked) or for the
// account-wide RevokeUserSessions path (lock/delete already send
// LockedMessage/DeletedMessage, which cover this same event at a higher
// severity). Gated by notify_session_revoked_by_admin (db.NotificationPrefs),
// default true - the one toggle here about someone *else's* action, not the
// account owner's own device/location, so it stays separate from the three
// anomaly-detection toggles above.
func SessionRevokedByAdminMessage(to, name, ip, userAgent, frontendBaseURL string, b Branding) Message {
	lang := b.Lang
	if ip == "" {
		ip = unknownText(lang)
	}
	if userAgent == "" {
		userAgent = unknownText(lang)
	}
	s := stringsFor(lang).SessionRevokedByAdmin
	vars := map[string]string{
		"instance":  b.InstanceName,
		"greeting":  greeting(name, lang),
		"ip":        ip,
		"device":    userAgent,
		"link":      strings.TrimRight(frontendBaseURL, "/"),
		"signature": signature(b.InstanceName, lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}

// AnomalyMessage is sent to a session's own owner when auth.checkAndRecordLoginCountry
// (a fresh login) or auth.ValidateSession's per-session country tracking (an
// already-issued session suddenly seen from a different CF-IPCountry mid-lifetime)
// detects a country change. This is the one channel that still reaches the
// account owner even if they have no other tab/device currently connected to
// receive the matching "session.new"/anomaly SSE push (internal/notify) -
// see that event's doc comment for why the live push alone is not enough.
// previousCountry is always a bare two-letter CF-IPCountry code (the stored
// baseline - see lastCountryTTL's doc comment, no historical city is ever
// kept). country is the "Now" value and, like LoginMessage's own country
// parameter, may be auth.mailLocation's city-enriched display string rather
// than a bare code - the anomaly comparison itself always happens on the
// plain codes before either mail function is ever called, this parameter is
// purely what gets displayed. Neither is ever empty here (both call sites
// only invoke this once they have already confirmed a genuine,
// known-to-known difference - see loginCountry's doc comment on ""
// meaning "anomaly detection not available", not "matches").
// Deliberately no link to a specific "block this session" action: the
// System Info / Profile sessions tables (already linked here) are where
// that already lives, and duplicating it risks the link going stale if
// that page's route ever moves.
func AnomalyMessage(to, name, ip, country, previousCountry, frontendBaseURL string, b Branding) Message {
	lang := b.Lang
	if ip == "" {
		ip = unknownText(lang)
	}
	s := stringsFor(lang).Anomaly
	vars := map[string]string{
		"instance":         b.InstanceName,
		"greeting":         greeting(name, lang),
		"previous_country": previousCountry,
		"country":          country,
		"ip":               ip,
		"link":             strings.TrimRight(frontendBaseURL, "/"),
		"signature":        signature(b.InstanceName, lang),
	}
	return Message{To: to, Subject: render(s.Subject, vars), Body: render(s.Body, vars)}
}
