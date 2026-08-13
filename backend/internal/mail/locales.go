package mail

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

// locales/*.json holds every system-mail string (account approved/locked/
// unlocked/deleted/pending-approval, new sign-in, new device, anomaly,
// session-revoked-by-admin) for every supportedLangs (branding.go) code -
// the mail package's own equivalent of the frontend's per-key locale JSON
// files (frontend/src/locales/*.json), just for full-sentence mail copy
// instead of short UI labels. Embedded into the binary rather than read
// from disk at runtime, so a mail send never depends on the working
// directory or an install step copying a locales/ folder alongside the
// binary.
//
// Placeholders are named ("{{instance}}", "{{link}}", ...) rather than
// positional %s verbs - deliberately, replacing the previous design where
// every language's subject/body pair lived in one Go map literal per
// message specifically so a mismatched %s count/order would be obvious at
// review time (see git history for that rationale). Named tokens make that
// whole failure mode structurally impossible: a token can't silently swap
// position the way two adjacent %s verbs could when a translator edits
// only one language's file, so the safety property that used to require
// "keep every language next to its siblings in one map" now comes from the
// substitution scheme itself, which is what makes it safe to split
// translations out into ordinary per-language JSON files the same way the
// frontend already does.
//
//go:embed locales/*.json
var localeFS embed.FS

type mailMsgStrings struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type mailCommonStrings struct {
	// Greeting/Signature/Unknown/NotProvided back greeting(), signature(),
	// unknownText(), notProvidedText() below - the small translated
	// fragments shared across multiple messages (every message opens with
	// Greeting and closes with Signature; Unknown/NotProvided fill in for
	// an empty ip/country/userAgent/requesterName).
	Greeting    string `json:"greeting"`
	Signature   string `json:"signature"`
	Unknown     string `json:"unknown"`
	NotProvided string `json:"not_provided"`
}

// mailLangStrings is the parsed shape of one locales/<code>.json file.
type mailLangStrings struct {
	Common                mailCommonStrings `json:"common"`
	Approved              mailMsgStrings    `json:"approved"`
	Locked                mailMsgStrings    `json:"locked"`
	Unlocked              mailMsgStrings    `json:"unlocked"`
	Deleted               mailMsgStrings    `json:"deleted"`
	PendingApproval       mailMsgStrings    `json:"pending_approval"`
	Login                 mailMsgStrings    `json:"login"`
	NewDevice             mailMsgStrings    `json:"new_device"`
	SessionRevokedByAdmin mailMsgStrings    `json:"session_revoked_by_admin"`
	Anomaly               mailMsgStrings    `json:"anomaly"`
}

// mailLocales holds every locales/<code>.json file, parsed once at package
// init - a bad embedded file is a build-time bug, so mustLoadMailLocales
// panics rather than returning an error no caller could sensibly handle.
var mailLocales = mustLoadMailLocales()

func mustLoadMailLocales() map[string]mailLangStrings {
	entries, err := localeFS.ReadDir("locales")
	if err != nil {
		panic(fmt.Sprintf("mail: reading embedded locales: %v", err))
	}
	out := make(map[string]mailLangStrings, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		code := strings.TrimSuffix(e.Name(), ".json")
		data, err := localeFS.ReadFile("locales/" + e.Name())
		if err != nil {
			panic(fmt.Sprintf("mail: reading locales/%s: %v", e.Name(), err))
		}
		var ls mailLangStrings
		if err := json.Unmarshal(data, &ls); err != nil {
			panic(fmt.Sprintf("mail: parsing locales/%s: %v", e.Name(), err))
		}
		out[code] = ls
	}
	return out
}

// stringsFor returns the parsed locale strings for lang, falling back to
// English for any language embed/locales doesn't have a file for -
// defensive only: lang is already validated against supportedLangs by
// CurrentBranding before it ever reaches here (see that function's own
// doc comment), so this only matters if a caller ever constructs a
// Branding by hand.
func stringsFor(lang string) mailLangStrings {
	if ls, ok := mailLocales[lang]; ok {
		return ls
	}
	return mailLocales["en"]
}

// render replaces every "{{key}}" token in tmpl with vars[key]. Extra keys
// in vars that don't appear in tmpl are simply unused (every call site
// below passes one vars map to both a message's Subject and Body template,
// even though Subject only ever references a subset of the keys Body
// needs) - harmless, and simpler than building two narrower maps per
// message.
func render(tmpl string, vars map[string]string) string {
	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// greeting renders "Hello {given name}," (English) or the equivalent
// opener in lang when name is known, or the bare "Hello," form when it is
// not (an IdP that never populated a display name - see oidcclient.go's
// Claims doc comment on Name being optional by nature). Only the first
// word of name is used - "Hello Max," not "Hello Max Mustermann," - on the
// assumption that Name is "given family" order, which holds for every IdP
// this codebase currently documents support for (Pocket ID, Authentik,
// Keycloak, Authelia all populate the standard OIDC "name" claim this
// way). Never falls back to the email address here: "Hello
// jane@example.com," reads like a templating bug, not a greeting.
func greeting(name, lang string) string {
	fields := strings.Fields(name)
	nameSuffix := ""
	if len(fields) > 0 {
		nameSuffix = " " + fields[0]
	}
	return render(stringsFor(lang).Common.Greeting, map[string]string{"name": nameSuffix})
}

// signature renders the closing "Best regards, The {instance name} Team"
// block, translated, with instanceName substituted for the product name.
func signature(instanceName, lang string) string {
	return render(stringsFor(lang).Common.Signature, map[string]string{"instance": instanceName})
}

// unknownText renders the "(unknown)" placeholder used by
// LoginMessage/NewDeviceMessage/AnomalyMessage whenever ip/country/
// userAgent could not be determined - translated so the whole mail reads
// in one language, not English leaking into an otherwise-German letter.
func unknownText(lang string) string {
	return stringsFor(lang).Common.Unknown
}

// notProvidedText renders PendingApprovalMessage's fallback for an empty
// requesterName - translated so the admin sees this is a known gap in the
// request, not a rendering bug, in whichever language the rest of the
// mail is in.
func notProvidedText(lang string) string {
	return stringsFor(lang).Common.NotProvided
}
