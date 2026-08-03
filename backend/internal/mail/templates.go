package mail

import (
	"fmt"
	"strings"
)

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
// Plain Go functions rather than a templating engine or external template
// files - each is one fixed letter with at most a couple of variables (a
// name, a link, the requester's details), which does not warrant the
// extra dependency. English throughout, matching the rest of the product
// (the Setup Wizard, login/pending screens, and admin UI are all
// English-only - see project history on the wizard's English-translation
// pass).
//
// All four follow the same shape - greeting, one short explanation,
// optionally a link or details block, a closing line, a signature - so an
// admin's inbox reads as one coherent product rather than four
// differently-worded one-liners.

const signature = "\nBest regards,\nThe ModuLab Team\n"

// greeting renders "Hello {given name}," when name is known, or a plain
// "Hello," when it is not (an IdP that never populated a display name -
// see oidcclient.go's Claims doc comment on Name being optional by
// nature). Only the first word of name is used - "Hello Max," not "Hello
// Max Mustermann," - on the assumption that Name is "given family" order,
// which holds for every IdP this codebase currently documents support for
// (Pocket ID, Authentik, Keycloak, Authelia all populate the standard
// OIDC "name" claim this way). Never falls back to the email address
// here: "Hello jane@example.com," reads like a templating bug, not a
// greeting.
func greeting(name string) string {
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return "Hello,"
	}
	return fmt.Sprintf("Hello %s,", fields[0])
}

// ApprovedMessage is sent once admin.ApproveUserHandler succeeds. name is
// the recipient's own display name (may be empty - see greeting above).
func ApprovedMessage(to, name, frontendBaseURL string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account is ready",
		Body: fmt.Sprintf(
			"%s\n\nGood news - an administrator has approved your ModuLab account. You can sign in right away:\n\n%s\n%s",
			greeting(name), frontendBaseURL, signature,
		),
	}
}

// LockedMessage is sent once admin.LockUserHandler succeeds. Deliberately
// carries no link back to the frontend - signing in again is exactly what
// this message needs to discourage, unlike the other three.
func LockedMessage(to, name string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account has been locked",
		Body: fmt.Sprintf(
			"%s\n\nAn administrator has locked your ModuLab account. You will not be able to sign in until it is unlocked again.\n\nIf you believe this was a mistake, please contact your administrator.\n%s",
			greeting(name), signature,
		),
	}
}

// UnlockedMessage is sent once admin.UnlockUserHandler succeeds.
func UnlockedMessage(to, name, frontendBaseURL string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account has been unlocked",
		Body: fmt.Sprintf(
			"%s\n\nYour ModuLab account has been unlocked by an administrator. You can sign in again:\n\n%s\n%s",
			greeting(name), frontendBaseURL, signature,
		),
	}
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
func DeletedMessage(to, name string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account has been deleted",
		Body: fmt.Sprintf(
			"%s\n\nYour ModuLab account has been deleted and your access has been revoked. If you sign in again later, you will need to be approved again, as if this were your first time.\n%s",
			greeting(name), signature,
		),
	}
}

// PendingApprovalMessage is sent to every current admin
// (db.Pool.ListAdmins) once a brand-new pending signup is created -
// CallbackHandler's wasNew && !approved case in handlers.go, the same
// moment that publishes the "user.pending" SSE event. to/name identify
// the *admin* being written to (for the greeting); requesterName/
// requesterEmail identify the person waiting for approval. requesterName
// may be empty (same optionality as everywhere else a display name comes
// from the IdP) - rendered as "(not provided)" rather than left blank, so
// the admin sees this is a known gap in the request, not a rendering bug.
func PendingApprovalMessage(to, name, frontendBaseURL, requesterName, requesterEmail string) Message {
	displayRequesterName := strings.TrimSpace(requesterName)
	if displayRequesterName == "" {
		displayRequesterName = "(not provided)"
	}
	return Message{
		To:      to,
		Subject: "New ModuLab account awaiting approval",
		Body: fmt.Sprintf(
			"%s\n\nA new account is waiting for your approval:\n\n  Name:  %s\n  Email: %s\n\nYou can review and approve this request here:\n\n  %s/admin/users\n%s",
			greeting(name), displayRequesterName, requesterEmail, strings.TrimRight(frontendBaseURL, "/"), signature,
		),
	}
}

// LoginMessage is sent on every successful login for a user who has
// notify_new_login enabled (db.NotificationPrefs, users.notify_new_login,
// default true) - unlike AnomalyMessage below, this is unconditional: no
// country/device comparison, just "you just signed in", the same category
// of mail Google/GitHub send on every new session by default. Users who
// find that too noisy (e.g. signing in from the same device daily) can turn
// it off from their Profile page without losing AnomalyMessage/
// NewDeviceMessage, which stay gated by their own separate toggles.
func LoginMessage(to, name, ip, country, userAgent, frontendBaseURL string) Message {
	if ip == "" {
		ip = "(unknown)"
	}
	if country == "" {
		country = "(unknown)"
	}
	if userAgent == "" {
		userAgent = "(unknown)"
	}
	return Message{
		To:      to,
		Subject: "New sign-in to your ModuLab account",
		Body: fmt.Sprintf(
			"%s\n\nYour ModuLab account was just signed in:\n\n  Country: %s\n  IP:      %s\n  Device:  %s\n\nIf this was you, no action is needed. If it wasn't, review and end your active sessions here:\n\n  %s/profile\n%s",
			greeting(name), country, ip, userAgent, strings.TrimRight(frontendBaseURL, "/"), signature,
		),
	}
}

// NewDeviceMessage is AnomalyMessage's device-based counterpart: sent when
// auth.checkSessionDeviceAnomaly (session.go) sees an already-active
// session's request suddenly carry a different User-Agent than the one
// recorded for it - a change that country-based detection cannot catch
// (same country, different device/browser), and unlike a fresh login, one a
// legitimate user's own browser would never produce on its own mid-session.
// Gated by notify_new_device (db.NotificationPrefs), default true.
func NewDeviceMessage(to, name, ip, previousUserAgent, currentUserAgent, frontendBaseURL string) Message {
	if ip == "" {
		ip = "(unknown)"
	}
	return Message{
		To:      to,
		Subject: "New device detected on your ModuLab account",
		Body: fmt.Sprintf(
			"%s\n\nAn already-signed-in session on your ModuLab account was just used from a different device/browser than before:\n\n  Previous: %s\n  Now:      %s\n  IP:       %s\n\nIf this was you (a browser update, a new machine), no action is needed. If it wasn't, review and end your active sessions here:\n\n  %s/profile\n%s",
			greeting(name), previousUserAgent, currentUserAgent, ip, strings.TrimRight(frontendBaseURL, "/"), signature,
		),
	}
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
func SessionRevokedByAdminMessage(to, name, ip, userAgent, frontendBaseURL string) Message {
	if ip == "" {
		ip = "(unknown)"
	}
	if userAgent == "" {
		userAgent = "(unknown)"
	}
	return Message{
		To:      to,
		Subject: "One of your ModuLab sessions was ended by an administrator",
		Body: fmt.Sprintf(
			"%s\n\nAn administrator has ended one of your active ModuLab sessions:\n\n  IP:     %s\n  Device: %s\n\nYou will need to sign in again on that device if you still need access there. If you have questions, contact your administrator. Your other sessions, if any, are unaffected - review them here:\n\n  %s/profile\n%s",
			greeting(name), ip, userAgent, strings.TrimRight(frontendBaseURL, "/"), signature,
		),
	}
}

// AnomalyMessage is sent to a session's own owner when auth.checkAndRecordLoginCountry
// (a fresh login) or auth.ValidateSession's per-session country tracking (an
// already-issued session suddenly seen from a different CF-IPCountry mid-lifetime)
// detects a country change. This is the one channel that still reaches the
// account owner even if they have no other tab/device currently connected to
// receive the matching "session.new"/anomaly SSE push (internal/notify) -
// see that event's doc comment for why the live push alone is not enough.
// previousCountry/country are both two-letter CF-IPCountry codes, never
// empty here (both call sites only invoke this once they have already
// confirmed a genuine, known-to-known difference - see loginCountry's doc
// comment on "" meaning "anomaly detection not available", not "matches").
// Deliberately no link to a specific "block this session" action: the
// System Info / Profile sessions tables (already linked here) are where
// that already lives, and duplicating it risks the link going stale if
// that page's route ever moves.
func AnomalyMessage(to, name, ip, country, previousCountry, frontendBaseURL string) Message {
	if ip == "" {
		ip = "(unknown)"
	}
	return Message{
		To:      to,
		Subject: "New sign-in location detected on your ModuLab account",
		Body: fmt.Sprintf(
			"%s\n\nYour ModuLab account was just used from a different country than usual:\n\n  Previous:  %s\n  Now:       %s\n  IP:        %s\n\nIf this was you (traveling, VPN, a new network), no action is needed. If it wasn't, review and end your active sessions here:\n\n  %s/profile\n%s",
			greeting(name), previousCountry, country, ip, strings.TrimRight(frontendBaseURL, "/"), signature,
		),
	}
}
