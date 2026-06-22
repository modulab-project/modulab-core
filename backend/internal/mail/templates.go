package mail

import "fmt"

// ApprovedMessage, LockedMessage, and UnlockedMessage build the email for
// spec section 3.5's user-facing account lifecycle events - an extension
// beyond the spec's own Mail-Queue table (which only routes System-Alert
// and critical audit-log entries to mail, both Super-Admin-only): SSE
// (internal/notify) only reaches a user who happens to be connected right
// now, so these give the same three events a channel that still reaches
// them later. Plain Go functions rather than a templating engine or
// external template files - each is one fixed paragraph with at most one
// variable (a link back to the frontend), which does not warrant the
// extra dependency.
//
// English throughout, matching the rest of the product (the Setup
// Wizard, login/pending screens, and admin UI are all English-only - see
// project history on the wizard's English-translation pass).

// ApprovedMessage is sent once admin.ApproveUserHandler succeeds.
func ApprovedMessage(to, frontendBaseURL string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account has been approved",
		Body: fmt.Sprintf(
			"An administrator has approved your ModuLab account. You can sign in now:\n\n%s\n",
			frontendBaseURL,
		),
	}
}

// LockedMessage is sent once admin.LockUserHandler succeeds. Deliberately
// carries no link back to the frontend - signing in again is exactly what
// this message needs to discourage, unlike Approved/Unlocked above and
// below.
func LockedMessage(to string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account has been locked",
		Body:    "An administrator has locked your ModuLab account. Contact your administrator if you believe this is a mistake.\n",
	}
}

// UnlockedMessage is sent once admin.UnlockUserHandler succeeds.
func UnlockedMessage(to, frontendBaseURL string) Message {
	return Message{
		To:      to,
		Subject: "Your ModuLab account has been unlocked",
		Body: fmt.Sprintf(
			"An administrator has unlocked your ModuLab account. You can sign in now:\n\n%s\n",
			frontendBaseURL,
		),
	}
}
