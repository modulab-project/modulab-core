// AdminGeneralHandler backs GET/PATCH /v1/admin/system/general - the
// "Sprache & Region" / "Instanz-Identität" settings page: which of the
// frontend's 5 supported UI languages (en/de/nl/es/fr) outgoing system mail
// is rendered in (see mail.Branding, mail.CurrentBranding, templates.go),
// and what display name replaces the literal "ModuLab" in those same
// mails. Both are plain core_settings string rows, same storage
// AdminLimitsHandler uses for its own cross-cutting settings - see that
// file's doc comment for why non-secret, instance-wide config lives there
// rather than in its own table.
//
// Deliberately its own small handler/route rather than folded into
// AdminLimitsHandler: limits are operational (rate limits, timeouts, pool
// sizes) and this is identity/localization - different admins reach for
// these at different times, and LimitsSettings's already-long field list
// (see its own doc comment) is not the place to also explain language
// codes and mail branding.
package adminapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
	"github.com/modulab-project/modulab-core/backend/internal/mail"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// GeneralSettings is the shape of GET/PATCH /v1/admin/system/general.
//
// Configurable settings:
//   - system_language: one of "en", "de", "nl", "es", "fr" - the language
//     mail.CurrentBranding resolves for every templates.go message from
//     this point on. Takes effect immediately, on the next mail sent -
//     see mail.CurrentBranding's doc comment on why it is re-resolved
//     per-message rather than cached.
//   - instance_name: free-text display name substituted for "ModuLab" in
//     mail subjects/signatures (e.g. a homelab operator naming their
//     instance after their household). Empty is rejected - PATCH with an
//     all-whitespace value falls back to mail.DefaultInstanceName instead
//     of storing a blank Team signature.
type GeneralSettings struct {
	SystemLanguage string `json:"system_language"`
	InstanceName   string `json:"instance_name"`
}

// currentGeneralSettings resolves GeneralSettings from core_settings via
// mail.CurrentBranding, the same reader every mail-sending call site uses -
// so this handler and the mails it configures can never disagree about
// what "current" means, same discipline currentLimitsSettings follows for
// LimitsSettings.
func currentGeneralSettings(r *http.Request, pool *db.Pool) GeneralSettings {
	b := mail.CurrentBranding(r.Context(), pool)
	return GeneralSettings{
		SystemLanguage: b.Lang,
		InstanceName:   b.InstanceName,
	}
}

// supportedGeneralLanguages is the PATCH-time validation counterpart to
// mail package's own (unexported) supportedLangs - kept as its own literal
// here rather than exported from mail, since mail has no other reason to
// expose a validation helper and this is the only other package that needs
// one.
var supportedGeneralLanguages = map[string]bool{
	"en": true,
	"de": true,
	"nl": true,
	"es": true,
	"fr": true,
}

// AdminGeneralHandler handles GET and PATCH /v1/admin/system/general.
// Auth is enforced by the superAdminOnly middleware in main.go, same as
// every other handler in this package.
func AdminGeneralHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		switch r.Method {
		case http.MethodGet:
			httperr.JSON(w, http.StatusOK, currentGeneralSettings(r, pool))

		case http.MethodPatch:
			var body GeneralSettings
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}

			if !supportedGeneralLanguages[body.SystemLanguage] {
				http.Error(w, "system_language must be one of: en, de, nl, es, fr", http.StatusBadRequest)
				return
			}
			instanceName := strings.TrimSpace(body.InstanceName)
			if instanceName == "" {
				http.Error(w, "instance_name must not be empty", http.StatusBadRequest)
				return
			}

			if err := pool.SetSetting(ctx, mail.SettingKeySystemLanguage, body.SystemLanguage); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			if err := pool.SetSetting(ctx, mail.SettingKeyInstanceName, instanceName); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}

			// Best-effort audit; a failed write must not block the response -
			// same reasoning as AdminLimitsHandler's own audit call.
			sess, _ := auth.SessionFromContext(ctx)
			if masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv); err == nil {
				detailsJSON, _ := json.Marshal(GeneralSettings{SystemLanguage: body.SystemLanguage, InstanceName: instanceName})
				if err := audit.Log(ctx, pool, masterKey, audit.LogParams{
					EventType:  audit.EventConfigSystemGeneral,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
					Details:    string(detailsJSON),
				}); err != nil {
					log.Printf("adminapi: audit general settings update: %v", err)
				}
			}

			httperr.JSON(w, http.StatusOK, GeneralSettings{SystemLanguage: body.SystemLanguage, InstanceName: instanceName})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
