// Branding backs GET/PATCH /v1/admin/system/general (adminapi.AdminGeneralHandler)
// - the "Sprache & Region" / "Instanz-Identität" admin settings page. Two
// values, both operator-configured and both affecting every template in
// templates.go: which of the frontend's 5 supported UI languages
// (frontend/src/locales/{en,de,nl,es,fr}.json) outgoing system mail is
// rendered in, and what display name replaces the literal "ModuLab" in
// mail subjects/signatures (e.g. a homelab operator naming their instance
// after their household). Both are plain core_settings string rows - see
// adminapi.LimitsSettings's doc comment for why cross-cutting,
// non-secret config lives there rather than in its own table.
//
// Deliberately instance-wide, not per-user: unlike the frontend's own
// i18n (a signed-in user's browser locale, or the language switcher in
// their own Profile page), there is exactly one recipient-independent
// choice to make for a lifecycle mail addressed to *any* account -
// see the project decision to keep this global rather than adding a
// per-user preferred_language column.
package mail

import (
	"context"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const (
	// SettingKeySystemLanguage/SettingKeyInstanceName are the core_settings
	// keys this file's CurrentBranding reads and adminapi.AdminGeneralHandler
	// writes - exported so that handler can key off these constants instead
	// of repeating the literal, the same "one definition, not two copies"
	// discipline adminapi.AdminLimitsHandler already follows for every one
	// of its own settings.
	SettingKeySystemLanguage = "system_language"
	SettingKeyInstanceName   = "instance_name"

	// DefaultLanguage/DefaultInstanceName are what a fresh install (or any
	// instance that has never visited the settings page) falls back to -
	// English, and the product's own name, exactly matching every mail
	// subject/signature before this file existed.
	DefaultLanguage     = "en"
	DefaultInstanceName = "ModuLab"
)

// supportedLangs mirrors the frontend's own supported set (project
// decision, see frontend/src/locales/*.json) - a value read back from
// core_settings that isn't one of these is treated as unset rather than
// risking a template lookup silently falling through to English for a
// language that was never actually a valid choice from the settings page.
var supportedLangs = map[string]bool{
	"en": true,
	"de": true,
	"nl": true,
	"es": true,
	"fr": true,
}

// Branding is the resolved (fallback-applied) pair of settings every
// templates.go function needs to render.
type Branding struct {
	Lang         string
	InstanceName string
}

// CurrentBranding resolves Branding from core_settings, re-read on every
// call rather than cached - the same "re-resolve every time" choice
// setup.ResolveSMTPConfig/ResolveOIDCConfig already make, so a change saved
// on the settings page takes effect on the very next mail sent, no Core
// restart required. Only ever called from the small number of auth package
// call sites that build a templates.go Message (session.go, handlers.go,
// admin.go), not from any hot path.
func CurrentBranding(ctx context.Context, pool *db.Pool) Branding {
	b := Branding{Lang: DefaultLanguage, InstanceName: DefaultInstanceName}

	if v, ok, err := pool.GetSetting(ctx, SettingKeySystemLanguage); err == nil && ok && supportedLangs[v] {
		b.Lang = v
	}
	if v, ok, err := pool.GetSetting(ctx, SettingKeyInstanceName); err == nil && ok && strings.TrimSpace(v) != "" {
		b.InstanceName = strings.TrimSpace(v)
	}
	return b
}
