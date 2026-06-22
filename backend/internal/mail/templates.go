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

// PendingApprovalMessage is sent to every current org-admin/super-admin
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
