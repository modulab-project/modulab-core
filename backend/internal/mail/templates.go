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
// Every function below takes a Branding (branding.go) as its last
// parameter and renders in b.Lang, falling back to English for any
// language not present in a given message's table (defensive only - b.Lang
// is already validated against supportedLangs by CurrentBranding, so this
// only matters if a caller ever constructs a Branding by hand). Every
// place the literal product name would otherwise appear uses
// b.InstanceName instead, so an operator who renamed their instance sees
// their own name throughout, not "ModuLab".
//
// Plain Go functions rather than a templating engine or external template
// files - each is one fixed letter with at most a handful of variables (a
// name, a link, the requester's details, now also lang/instance name),
// which does not warrant the extra dependency. Translations are
// maintained by hand alongside the English original in the same map
// literal, one per function, rather than in separate locale files - unlike
// the frontend's per-key JSON files (frontend/src/locales/*.json), these
// are full sentences with embedded %s placeholders whose order must match
// the Sprintf call exactly, so keeping each language's version physically
// next to its siblings (same function, one map) makes a mismatched
// placeholder count/order obvious at review time in a way that scattering
// them across 5 separate files would not.
//
// All five (Approved/Locked/Unlocked/Deleted/PendingApproval, plus the
// four session/anomaly mails further down) follow the same shape -
// greeting, one short explanation, optionally a link or details block, a
// closing line, a signature - so an admin's inbox reads as one coherent
// product rather than differently-worded one-liners.

// localize picks table[lang], falling back to table["en"] if lang has no
// entry - see the package doc comment above on why this can only happen
// defensively, given CurrentBranding already validates lang.
func localize(lang string, table map[string][2]string) (subject, bodyTemplate string) {
	if t, ok := table[lang]; ok {
		return t[0], t[1]
	}
	t := table["en"]
	return t[0], t[1]
}

// greetingTemplates/greeting render "Hello {given name}," (English) or the
// equivalent opener in b.Lang when name is known, or the bare "Hello," form
// when it is not (an IdP that never populated a display name - see
// oidcclient.go's Claims doc comment on Name being optional by nature).
// Only the first word of name is used - "Hello Max," not "Hello Max
// Mustermann," - on the assumption that Name is "given family" order,
// which holds for every IdP this codebase currently documents support for
// (Pocket ID, Authentik, Keycloak, Authelia all populate the standard OIDC
// "name" claim this way). Never falls back to the email address here:
// "Hello jane@example.com," reads like a templating bug, not a greeting.
var greetingTemplates = map[string]string{
	"en": "Hello%s,",
	"de": "Hallo%s,",
	"nl": "Hallo%s,",
	"es": "Hola%s,",
	"fr": "Bonjour%s,",
}

func greeting(name, lang string) string {
	tmpl, ok := greetingTemplates[lang]
	if !ok {
		tmpl = greetingTemplates["en"]
	}
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return strings.Replace(tmpl, "%s", "", 1)
	}
	return fmt.Sprintf(tmpl, " "+fields[0])
}

// signatureTemplates/signature render the closing "Best regards, The
// {instance name} Team" block, translated, with b.InstanceName substituted
// for the product name.
var signatureTemplates = map[string]string{
	"en": "\nBest regards,\nThe %s Team\n",
	"de": "\nViele Grüße,\nIhr %s-Team\n",
	"nl": "\nMet vriendelijke groet,\nHet %s-team\n",
	"es": "\nSaludos cordiales,\nEl equipo de %s\n",
	"fr": "\nCordialement,\nL'équipe %s\n",
}

func signature(instanceName, lang string) string {
	tmpl, ok := signatureTemplates[lang]
	if !ok {
		tmpl = signatureTemplates["en"]
	}
	return fmt.Sprintf(tmpl, instanceName)
}

// unknownTemplates/unknownText render the "(unknown)" placeholder used by
// LoginMessage/NewDeviceMessage/AnomalyMessage whenever ip/country/
// userAgent could not be determined - translated so the whole mail reads
// in one language, not English leaking into an otherwise-German letter.
var unknownTemplates = map[string]string{
	"en": "(unknown)",
	"de": "(unbekannt)",
	"nl": "(onbekend)",
	"es": "(desconocido)",
	"fr": "(inconnu)",
}

func unknownText(lang string) string {
	if t, ok := unknownTemplates[lang]; ok {
		return t
	}
	return unknownTemplates["en"]
}

// ApprovedMessage is sent once admin.ApproveUserHandler succeeds. name is
// the recipient's own display name (may be empty - see greeting above).
func ApprovedMessage(to, name, frontendBaseURL string, b Branding) Message {
	table := map[string][2]string{
		"en": {
			"Your %s account is ready",
			"%s\n\nGood news - an administrator has approved your %s account. You can sign in right away:\n\n%s\n%s",
		},
		"de": {
			"Ihr %s-Konto ist bereit",
			"%s\n\nGute Nachrichten – ein Administrator hat Ihr %s-Konto freigegeben. Sie können sich jetzt anmelden:\n\n%s\n%s",
		},
		"nl": {
			"Uw %s-account is klaar",
			"%s\n\nGoed nieuws - een beheerder heeft uw %s-account goedgekeurd. U kunt direct inloggen:\n\n%s\n%s",
		},
		"es": {
			"Su cuenta de %s está lista",
			"%s\n\nBuenas noticias: un administrador ha aprobado su cuenta de %s. Ya puede iniciar sesión:\n\n%s\n%s",
		},
		"fr": {
			"Votre compte %s est prêt",
			"%s\n\nBonne nouvelle : un administrateur a approuvé votre compte %s. Vous pouvez vous connecter dès maintenant :\n\n%s\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body:    fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, frontendBaseURL, signature(b.InstanceName, b.Lang)),
	}
}

// LockedMessage is sent once admin.LockUserHandler succeeds. Deliberately
// carries no link back to the frontend - signing in again is exactly what
// this message needs to discourage, unlike the other four.
func LockedMessage(to, name string, b Branding) Message {
	table := map[string][2]string{
		"en": {
			"Your %s account has been locked",
			"%s\n\nAn administrator has locked your %s account. You will not be able to sign in until it is unlocked again.\n\nIf you believe this was a mistake, please contact your administrator.\n%s",
		},
		"de": {
			"Ihr %s-Konto wurde gesperrt",
			"%s\n\nEin Administrator hat Ihr %s-Konto gesperrt. Sie können sich erst wieder anmelden, wenn es entsperrt wurde.\n\nWenn Sie glauben, dass dies ein Irrtum ist, wenden Sie sich bitte an Ihren Administrator.\n%s",
		},
		"nl": {
			"Uw %s-account is vergrendeld",
			"%s\n\nEen beheerder heeft uw %s-account vergrendeld. U kunt pas weer inloggen zodra het is ontgrendeld.\n\nAls u denkt dat dit een vergissing is, neem dan contact op met uw beheerder.\n%s",
		},
		"es": {
			"Su cuenta de %s ha sido bloqueada",
			"%s\n\nUn administrador ha bloqueado su cuenta de %s. No podrá iniciar sesión hasta que se desbloquee de nuevo.\n\nSi cree que esto es un error, póngase en contacto con su administrador.\n%s",
		},
		"fr": {
			"Votre compte %s a été verrouillé",
			"%s\n\nUn administrateur a verrouillé votre compte %s. Vous ne pourrez pas vous connecter tant qu'il n'aura pas été déverrouillé.\n\nSi vous pensez qu'il s'agit d'une erreur, contactez votre administrateur.\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body:    fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, signature(b.InstanceName, b.Lang)),
	}
}

// UnlockedMessage is sent once admin.UnlockUserHandler succeeds.
func UnlockedMessage(to, name, frontendBaseURL string, b Branding) Message {
	table := map[string][2]string{
		"en": {
			"Your %s account has been unlocked",
			"%s\n\nYour %s account has been unlocked by an administrator. You can sign in again:\n\n%s\n%s",
		},
		"de": {
			"Ihr %s-Konto wurde entsperrt",
			"%s\n\nIhr %s-Konto wurde von einem Administrator entsperrt. Sie können sich wieder anmelden:\n\n%s\n%s",
		},
		"nl": {
			"Uw %s-account is ontgrendeld",
			"%s\n\nUw %s-account is door een beheerder ontgrendeld. U kunt weer inloggen:\n\n%s\n%s",
		},
		"es": {
			"Su cuenta de %s ha sido desbloqueada",
			"%s\n\nSu cuenta de %s ha sido desbloqueada por un administrador. Ya puede volver a iniciar sesión:\n\n%s\n%s",
		},
		"fr": {
			"Votre compte %s a été déverrouillé",
			"%s\n\nVotre compte %s a été déverrouillé par un administrateur. Vous pouvez vous reconnecter :\n\n%s\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body:    fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, frontendBaseURL, signature(b.InstanceName, b.Lang)),
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
func DeletedMessage(to, name string, b Branding) Message {
	table := map[string][2]string{
		"en": {
			"Your %s account has been deleted",
			"%s\n\nYour %s account has been deleted and your access has been revoked. If you sign in again later, you will need to be approved again, as if this were your first time.\n%s",
		},
		"de": {
			"Ihr %s-Konto wurde gelöscht",
			"%s\n\nIhr %s-Konto wurde gelöscht und Ihr Zugriff wurde entzogen. Wenn Sie sich später erneut anmelden, müssen Sie erneut freigegeben werden, so als wäre es Ihr erstes Mal.\n%s",
		},
		"nl": {
			"Uw %s-account is verwijderd",
			"%s\n\nUw %s-account is verwijderd en uw toegang is ingetrokken. Als u zich later opnieuw aanmeldt, moet u opnieuw worden goedgekeurd, alsof het uw eerste keer is.\n%s",
		},
		"es": {
			"Su cuenta de %s ha sido eliminada",
			"%s\n\nSu cuenta de %s ha sido eliminada y se ha revocado su acceso. Si inicia sesión de nuevo más adelante, deberá ser aprobado otra vez, como si fuera la primera vez.\n%s",
		},
		"fr": {
			"Votre compte %s a été supprimé",
			"%s\n\nVotre compte %s a été supprimé et votre accès a été révoqué. Si vous vous reconnectez plus tard, vous devrez être approuvé à nouveau, comme si c'était la première fois.\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body:    fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, signature(b.InstanceName, b.Lang)),
	}
}

// notProvidedTemplates/notProvidedText render PendingApprovalMessage's
// fallback for an empty requesterName - translated so the admin sees this
// is a known gap in the request, not a rendering bug, in whichever
// language the rest of the mail is in.
var notProvidedTemplates = map[string]string{
	"en": "(not provided)",
	"de": "(nicht angegeben)",
	"nl": "(niet opgegeven)",
	"es": "(no proporcionado)",
	"fr": "(non renseigné)",
}

func notProvidedText(lang string) string {
	if t, ok := notProvidedTemplates[lang]; ok {
		return t
	}
	return notProvidedTemplates["en"]
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
	table := map[string][2]string{
		"en": {
			"New %s account awaiting approval",
			"%s\n\nA new account is waiting for your approval:\n\n  Name:  %s\n  Email: %s\n\nYou can review and approve this request here:\n\n  %s/admin/users\n%s",
		},
		"de": {
			"Neues %s-Konto wartet auf Freigabe",
			"%s\n\nEin neues Konto wartet auf Ihre Freigabe:\n\n  Name:    %s\n  E-Mail:  %s\n\nSie können diese Anfrage hier prüfen und freigeben:\n\n  %s/admin/users\n%s",
		},
		"nl": {
			"Nieuw %s-account wacht op goedkeuring",
			"%s\n\nEr wacht een nieuw account op uw goedkeuring:\n\n  Naam:   %s\n  E-mail: %s\n\nU kunt dit verzoek hier bekijken en goedkeuren:\n\n  %s/admin/users\n%s",
		},
		"es": {
			"Nueva cuenta de %s pendiente de aprobación",
			"%s\n\nHay una nueva cuenta esperando su aprobación:\n\n  Nombre:  %s\n  Correo:  %s\n\nPuede revisar y aprobar esta solicitud aquí:\n\n  %s/admin/users\n%s",
		},
		"fr": {
			"Nouveau compte %s en attente d'approbation",
			"%s\n\nUn nouveau compte attend votre approbation :\n\n  Nom :     %s\n  E-mail :  %s\n\nVous pouvez examiner et approuver cette demande ici :\n\n  %s/admin/users\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body: fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), displayRequesterName, requesterEmail,
			strings.TrimRight(frontendBaseURL, "/"), signature(b.InstanceName, b.Lang)),
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
//
// country is despite its name a display-only location string, not
// necessarily a bare CF-IPCountry code any more: callers pass
// auth.mailLocation's result, which prepends internal/geoip's city lookup
// ("Frankfurt am Main, DE") when GeoIP is configured and has data for the
// login's IP, falling back to the plain country code otherwise. Never used
// for any comparison here - purely the "Location:" line's value.
func LoginMessage(to, name, ip, country, userAgent, frontendBaseURL string, b Branding) Message {
	if ip == "" {
		ip = unknownText(b.Lang)
	}
	if country == "" {
		country = unknownText(b.Lang)
	}
	if userAgent == "" {
		userAgent = unknownText(b.Lang)
	}
	table := map[string][2]string{
		"en": {
			"New sign-in to your %s account",
			"%s\n\nYour %s account was just signed in:\n\n  Location: %s\n  IP:       %s\n  Device:   %s\n\nIf this was you, no action is needed. If it wasn't, review and end your active sessions here:\n\n  %s/profile\n%s",
		},
		"de": {
			"Neue Anmeldung bei Ihrem %s-Konto",
			"%s\n\nBei Ihrem %s-Konto wurde soeben eine Anmeldung durchgeführt:\n\n  Standort: %s\n  IP:       %s\n  Gerät:    %s\n\nWenn Sie das waren, ist keine Aktion erforderlich. Falls nicht, überprüfen und beenden Sie Ihre aktiven Sitzungen hier:\n\n  %s/profile\n%s",
		},
		"nl": {
			"Nieuwe aanmelding bij uw %s-account",
			"%s\n\nEr is zojuist ingelogd op uw %s-account:\n\n  Locatie:  %s\n  IP:       %s\n  Apparaat: %s\n\nAls u dit was, is geen actie nodig. Zo niet, controleer en beëindig uw actieve sessies hier:\n\n  %s/profile\n%s",
		},
		"es": {
			"Nuevo inicio de sesión en su cuenta de %s",
			"%s\n\nSe acaba de iniciar sesión en su cuenta de %s:\n\n  Ubicación:   %s\n  IP:          %s\n  Dispositivo: %s\n\nSi fue usted, no es necesario hacer nada. Si no fue usted, revise y finalice sus sesiones activas aquí:\n\n  %s/profile\n%s",
		},
		"fr": {
			"Nouvelle connexion à votre compte %s",
			"%s\n\nVotre compte %s vient de faire l'objet d'une connexion :\n\n  Lieu :     %s\n  IP :       %s\n  Appareil : %s\n\nSi c'était vous, aucune action n'est nécessaire. Sinon, consultez et mettez fin à vos sessions actives ici :\n\n  %s/profile\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body: fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, country, ip, userAgent,
			strings.TrimRight(frontendBaseURL, "/"), signature(b.InstanceName, b.Lang)),
	}
}

// NewDeviceMessage is AnomalyMessage's device-based counterpart: sent when
// auth.checkSessionDeviceAnomaly (session.go) sees an already-active
// session's request suddenly carry a different User-Agent than the one
// recorded for it - a change that country-based detection cannot catch
// (same country, different device/browser), and unlike a fresh login, one a
// legitimate user's own browser would never produce on its own mid-session.
// Gated by notify_new_device (db.NotificationPrefs), default true.
func NewDeviceMessage(to, name, ip, previousUserAgent, currentUserAgent, frontendBaseURL string, b Branding) Message {
	if ip == "" {
		ip = unknownText(b.Lang)
	}
	table := map[string][2]string{
		"en": {
			"New device detected on your %s account",
			"%s\n\nAn already-signed-in session on your %s account was just used from a different device/browser than before:\n\n  Previous: %s\n  Now:      %s\n  IP:       %s\n\nIf this was you (a browser update, a new machine), no action is needed. If it wasn't, review and end your active sessions here:\n\n  %s/profile\n%s",
		},
		"de": {
			"Neues Gerät bei Ihrem %s-Konto erkannt",
			"%s\n\nEine bereits angemeldete Sitzung Ihres %s-Kontos wurde soeben von einem anderen Gerät/Browser als zuvor verwendet:\n\n  Vorher: %s\n  Jetzt:  %s\n  IP:     %s\n\nWenn Sie das waren (Browser-Update, neues Gerät), ist keine Aktion erforderlich. Falls nicht, überprüfen und beenden Sie Ihre aktiven Sitzungen hier:\n\n  %s/profile\n%s",
		},
		"nl": {
			"Nieuw apparaat gedetecteerd bij uw %s-account",
			"%s\n\nEen reeds aangemelde sessie van uw %s-account werd zojuist gebruikt vanaf een ander apparaat/browser dan voorheen:\n\n  Voorheen: %s\n  Nu:       %s\n  IP:       %s\n\nAls u dit was (browserupdate, nieuwe machine), is geen actie nodig. Zo niet, controleer en beëindig uw actieve sessies hier:\n\n  %s/profile\n%s",
		},
		"es": {
			"Nuevo dispositivo detectado en su cuenta de %s",
			"%s\n\nUna sesión ya iniciada en su cuenta de %s se acaba de usar desde un dispositivo/navegador distinto al anterior:\n\n  Antes:  %s\n  Ahora:  %s\n  IP:     %s\n\nSi fue usted (una actualización del navegador, un equipo nuevo), no es necesario hacer nada. Si no fue usted, revise y finalice sus sesiones activas aquí:\n\n  %s/profile\n%s",
		},
		"fr": {
			"Nouvel appareil détecté sur votre compte %s",
			"%s\n\nUne session déjà connectée sur votre compte %s vient d'être utilisée depuis un appareil/navigateur différent :\n\n  Avant :      %s\n  Maintenant : %s\n  IP :         %s\n\nSi c'était vous (mise à jour du navigateur, nouvel appareil), aucune action n'est nécessaire. Sinon, consultez et mettez fin à vos sessions actives ici :\n\n  %s/profile\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body: fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, previousUserAgent, currentUserAgent, ip,
			strings.TrimRight(frontendBaseURL, "/"), signature(b.InstanceName, b.Lang)),
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
func SessionRevokedByAdminMessage(to, name, ip, userAgent, frontendBaseURL string, b Branding) Message {
	if ip == "" {
		ip = unknownText(b.Lang)
	}
	if userAgent == "" {
		userAgent = unknownText(b.Lang)
	}
	table := map[string][2]string{
		"en": {
			"One of your %s sessions was ended by an administrator",
			"%s\n\nAn administrator has ended one of your active %s sessions:\n\n  IP:     %s\n  Device: %s\n\nYou will need to sign in again on that device if you still need access there. If you have questions, contact your administrator. Your other sessions, if any, are unaffected - review them here:\n\n  %s/profile\n%s",
		},
		"de": {
			"Eine Ihrer %s-Sitzungen wurde von einem Administrator beendet",
			"%s\n\nEin Administrator hat eine Ihrer aktiven %s-Sitzungen beendet:\n\n  IP:     %s\n  Gerät:  %s\n\nSie müssen sich auf diesem Gerät erneut anmelden, wenn Sie dort weiterhin Zugriff benötigen. Bei Fragen wenden Sie sich an Ihren Administrator. Ihre anderen Sitzungen, falls vorhanden, sind nicht betroffen - überprüfen Sie diese hier:\n\n  %s/profile\n%s",
		},
		"nl": {
			"Een van uw %s-sessies is beëindigd door een beheerder",
			"%s\n\nEen beheerder heeft een van uw actieve %s-sessies beëindigd:\n\n  IP:       %s\n  Apparaat: %s\n\nU moet opnieuw inloggen op dat apparaat als u daar nog steeds toegang nodig heeft. Neem bij vragen contact op met uw beheerder. Uw overige sessies, indien aanwezig, zijn niet beïnvloed - bekijk ze hier:\n\n  %s/profile\n%s",
		},
		"es": {
			"Un administrador ha finalizado una de sus sesiones de %s",
			"%s\n\nUn administrador ha finalizado una de sus sesiones activas de %s:\n\n  IP:           %s\n  Dispositivo:  %s\n\nDeberá volver a iniciar sesión en ese dispositivo si aún necesita acceso allí. Si tiene preguntas, póngase en contacto con su administrador. El resto de sus sesiones, si las hay, no se ven afectadas: revíselas aquí:\n\n  %s/profile\n%s",
		},
		"fr": {
			"Une de vos sessions %s a été fermée par un administrateur",
			"%s\n\nUn administrateur a mis fin à l'une de vos sessions actives %s :\n\n  IP :      %s\n  Appareil : %s\n\nVous devrez vous reconnecter sur cet appareil si vous avez encore besoin d'y accéder. Pour toute question, contactez votre administrateur. Vos autres sessions, le cas échéant, ne sont pas affectées - consultez-les ici :\n\n  %s/profile\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body: fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, ip, userAgent,
			strings.TrimRight(frontendBaseURL, "/"), signature(b.InstanceName, b.Lang)),
	}
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
	if ip == "" {
		ip = unknownText(b.Lang)
	}
	table := map[string][2]string{
		"en": {
			"New sign-in location detected on your %s account",
			"%s\n\nYour %s account was just used from a different country than usual:\n\n  Previous:  %s\n  Now:       %s\n  IP:        %s\n\nIf this was you (traveling, VPN, a new network), no action is needed. If it wasn't, review and end your active sessions here:\n\n  %s/profile\n%s",
		},
		"de": {
			"Neuer Anmeldeort bei Ihrem %s-Konto erkannt",
			"%s\n\nIhr %s-Konto wurde soeben aus einem anderen Land als üblich verwendet:\n\n  Vorher: %s\n  Jetzt:  %s\n  IP:     %s\n\nWenn Sie das waren (Reise, VPN, neues Netzwerk), ist keine Aktion erforderlich. Falls nicht, überprüfen und beenden Sie Ihre aktiven Sitzungen hier:\n\n  %s/profile\n%s",
		},
		"nl": {
			"Nieuwe aanmeldlocatie gedetecteerd bij uw %s-account",
			"%s\n\nUw %s-account is zojuist gebruikt vanuit een ander land dan gebruikelijk:\n\n  Voorheen: %s\n  Nu:       %s\n  IP:       %s\n\nAls u dit was (op reis, VPN, nieuw netwerk), is geen actie nodig. Zo niet, controleer en beëindig uw actieve sessies hier:\n\n  %s/profile\n%s",
		},
		"es": {
			"Nueva ubicación de inicio de sesión detectada en su cuenta de %s",
			"%s\n\nSu cuenta de %s se acaba de usar desde un país distinto al habitual:\n\n  Antes:  %s\n  Ahora:  %s\n  IP:     %s\n\nSi fue usted (viaje, VPN, red nueva), no es necesario hacer nada. Si no fue usted, revise y finalice sus sesiones activas aquí:\n\n  %s/profile\n%s",
		},
		"fr": {
			"Nouvel emplacement de connexion détecté sur votre compte %s",
			"%s\n\nVotre compte %s vient d'être utilisé depuis un pays différent de d'habitude :\n\n  Avant :      %s\n  Maintenant : %s\n  IP :         %s\n\nSi c'était vous (voyage, VPN, nouveau réseau), aucune action n'est nécessaire. Sinon, consultez et mettez fin à vos sessions actives ici :\n\n  %s/profile\n%s",
		},
	}
	subjectTmpl, bodyTmpl := localize(b.Lang, table)
	return Message{
		To:      to,
		Subject: fmt.Sprintf(subjectTmpl, b.InstanceName),
		Body: fmt.Sprintf(bodyTmpl, greeting(name, b.Lang), b.InstanceName, previousCountry, country, ip,
			strings.TrimRight(frontendBaseURL, "/"), signature(b.InstanceName, b.Lang)),
	}
}
