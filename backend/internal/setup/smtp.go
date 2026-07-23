// This file implements SMTP configuration for spec section 3.5's
// Mail-Queue ("SMTP-Konfiguration im Admin-Panel. Kompatibel mit
// self-hosted Lösungen (Postfix, Mailcow, Stalwart) – kein externer
// Mail-Service erforderlich."). Unlike OIDC (oidc.go), this is deliberately
// NOT part of the Setup Wizard's fixed 6-step sequence or its
// bootstrap-token gate: the spec places it in the ongoing Admin Panel, not
// first-run setup, since a fresh install is perfectly usable without
// outbound mail (SSE notifications alone already cover the same events in
// real time for anyone currently connected - see internal/notify). main.go
// wires this behind a super-admin session check instead of
// bootstrap.Manager's middleware.
//
// Same encrypted-at-rest treatment as the OIDC client secret: the password
// is the one field spec section 2.4's data-category table would classify
// 🔴 Kritisch (OAuth-Secrets/API-Tokens tier, Class B/AES-GCM), so it goes
// through crypto.Encrypt before ever reaching core_settings, exactly like
// oidc.go's ClientSecret.
//
// Host/Username/FromAddress are encrypted with AES-256-GCM alongside the
// password, following spec section 2.4's encrypt-everything principle.
// Port and the encryption mode flag (smtp_encryption) are left as plaintext:
// they carry no PII and encrypting them would prevent simple existence checks
// and is unnecessary per the spec's 🟢 Unkritisch classification for purely
// technical values.
package setup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
)

const (
	smtpHostSettingKey        = "smtp_host"
	smtpPortSettingKey        = "smtp_port"
	smtpUsernameSettingKey    = "smtp_username"
	smtpPasswordSettingKey    = "smtp_password_enc"
	smtpFromAddressSettingKey = "smtp_from_address"
	smtpEncryptionSettingKey  = "smtp_encryption"

	// smtpUseTLSSettingKeyLegacy is the boolean field this replaced
	// (pre-implicit-TLS support: "true" meant STARTTLS, "false" meant
	// none - there was no third option). No longer written by
	// SMTPConfigureHandler, but still read as a fallback by
	// ResolveSMTPConfig/SMTPStatusHandler for any instance that
	// configured SMTP before smtpEncryptionSettingKey existed, so an
	// upgrade does not silently revert a working STARTTLS relay to
	// unencrypted. SMTPDeleteHandler still clears it too, so a fresh
	// instance has no trace of it either way.
	smtpUseTLSSettingKeyLegacy = "smtp_use_tls"
)

// Encryption mode values for SMTPConfigRequest.Encryption /
// SMTPRuntimeConfig.Encryption - see mail/smtp.go's send for what each one
// actually does on the wire.
const (
	SMTPEncryptionNone     = "none"     // Plaintext - same-LAN relay, no TLS at any point.
	SMTPEncryptionSTARTTLS = "starttls" // Connect plaintext, then upgrade (commonly port 587).
	SMTPEncryptionTLS      = "tls"      // TLS from the very first byte, a.k.a. "SSL" (commonly port 465).
)

// SMTPConfigRequest is the body of POST /v1/admin/smtp/configure.
// Username/Password may both be empty for a relay that allows
// unauthenticated submission from Core's own network (common for a
// same-LAN Postfix/Mailcow instance) - unlike OIDC's ClientSecret, an
// empty password is not rejected as a missing required field.
type SMTPConfigRequest struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
	// Encryption is one of SMTPEncryptionNone/STARTTLS/TLS. Empty is
	// treated as SMTPEncryptionSTARTTLS (the most common relay setup, and
	// what the previous boolean-only field defaulted its checkbox to) -
	// see SMTPConfigureHandler.
	Encryption string `json:"encryption"`
}

// SMTPStatusResponse reports the non-secret half of the configuration.
// Password is never included, mirroring OIDCStatusResponse's treatment of
// the client secret - Username is shown (an admin needs to recognize
// which account this is, the same way OIDCStatusResponse shows ClientID
// but not ClientSecret).
type SMTPStatusResponse struct {
	Configured  bool   `json:"configured"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Username    string `json:"username,omitempty"`
	FromAddress string `json:"from_address,omitempty"`
	Encryption  string `json:"encryption,omitempty"`
}

// SMTPRuntimeConfig is the fully resolved SMTP configuration the mail
// worker (internal/mail) needs to actually send a message. Like
// OIDCRuntimeConfig, never serialized to an HTTP response - Password has
// already been decrypted, so callers must not log it.
type SMTPRuntimeConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	Encryption  string
}

// SMTPConfigured reports whether SMTP has already been configured. Used
// by the mail worker to decide whether there is anything to do at all -
// an instance that never configured SMTP simply leaves queued mail
// unsent rather than erroring, see internal/mail's worker loop.
func SMTPConfigured(ctx context.Context, pool *db.Pool) (bool, error) {
	_, exists, err := pool.GetSetting(ctx, smtpHostSettingKey)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// ResolveSMTPConfig returns the effective SMTP configuration as persisted
// by /v1/admin/smtp/configure, with Password decrypted using masterKey.
// Re-resolved on every send attempt by the mail worker (not cached), so a
// configuration change in the admin panel takes effect on the very next
// queued message without a Core restart - same pattern as
// ResolveOIDCConfig.
func ResolveSMTPConfig(ctx context.Context, pool *db.Pool, masterKey string) (SMTPRuntimeConfig, error) {
	encHost, exists, err := pool.GetSetting(ctx, smtpHostSettingKey)
	if err != nil {
		return SMTPRuntimeConfig{}, err
	}
	if !exists {
		return SMTPRuntimeConfig{}, fmt.Errorf("setup: smtp has not been configured yet (call /v1/admin/smtp/configure first)")
	}
	host, err := crypto.DecryptIfNotEmpty(masterKey, encHost)
	if err != nil {
		return SMTPRuntimeConfig{}, fmt.Errorf("setup: decrypt smtp_host: %w", err)
	}
	portStr, _, err := pool.GetSetting(ctx, smtpPortSettingKey)
	if err != nil {
		return SMTPRuntimeConfig{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return SMTPRuntimeConfig{}, fmt.Errorf("setup: stored smtp port %q is not a number: %w", portStr, err)
	}
	encUsername, _, err := pool.GetSetting(ctx, smtpUsernameSettingKey)
	if err != nil {
		return SMTPRuntimeConfig{}, err
	}
	username, err := crypto.DecryptIfNotEmpty(masterKey, encUsername)
	if err != nil {
		return SMTPRuntimeConfig{}, fmt.Errorf("setup: decrypt smtp_username: %w", err)
	}
	encFromAddress, _, err := pool.GetSetting(ctx, smtpFromAddressSettingKey)
	if err != nil {
		return SMTPRuntimeConfig{}, err
	}
	fromAddress, err := crypto.DecryptIfNotEmpty(masterKey, encFromAddress)
	if err != nil {
		return SMTPRuntimeConfig{}, fmt.Errorf("setup: decrypt smtp_from_address: %w", err)
	}
	encryption, err := resolveSMTPEncryption(ctx, pool)
	if err != nil {
		return SMTPRuntimeConfig{}, err
	}

	var password string
	if encryptedPassword, exists, err := pool.GetSetting(ctx, smtpPasswordSettingKey); err != nil {
		return SMTPRuntimeConfig{}, err
	} else if exists && encryptedPassword != "" {
		// Decrypting an empty string back to an empty string would still
		// work, but skipped anyway - an unauthenticated relay (see
		// SMTPConfigRequest's doc comment) never had anything encrypted
		// for it in the first place, so there is nothing to decrypt.
		password, err = crypto.Decrypt(masterKey, encryptedPassword)
		if err != nil {
			return SMTPRuntimeConfig{}, fmt.Errorf("setup: decrypt smtp password: %w", err)
		}
	}

	return SMTPRuntimeConfig{
		Host:        host,
		Port:        port,
		Username:    username,
		Password:    password,
		FromAddress: fromAddress,
		Encryption:  encryption,
	}, nil
}

// resolveSMTPEncryption reads smtpEncryptionSettingKey, falling back to
// the legacy boolean (smtpUseTLSSettingKeyLegacy) for any instance
// configured before the three-way encryption setting existed - "true"
// becomes SMTPEncryptionSTARTTLS (the only kind of TLS the old boolean
// could mean), "false" or unset becomes SMTPEncryptionNone. Shared by
// ResolveSMTPConfig and SMTPStatusHandler so both fall back identically.
func resolveSMTPEncryption(ctx context.Context, pool *db.Pool) (string, error) {
	encryption, exists, err := pool.GetSetting(ctx, smtpEncryptionSettingKey)
	if err != nil {
		return "", err
	}
	if exists && encryption != "" {
		return encryption, nil
	}
	legacy, _, err := pool.GetSetting(ctx, smtpUseTLSSettingKeyLegacy)
	if err != nil {
		return "", err
	}
	if legacy == "true" {
		return SMTPEncryptionSTARTTLS, nil
	}
	return SMTPEncryptionNone, nil
}

// SMTPStatusHandler reports whether SMTP has been configured, and if so,
// every field except the password. masterKey is required to decrypt the
// host, username, and from_address fields stored as ciphertext since the
// encrypt-everything migration (spec section 2.4).
func SMTPStatusHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		encHost, exists, err := pool.GetSetting(ctx, smtpHostSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, SMTPStatusResponse{Configured: false})
			return
		}

		host, err := crypto.DecryptIfNotEmpty(masterKey, encHost)
		if err != nil {
			http.Error(w, fmt.Sprintf("decrypt smtp_host: %v", err), http.StatusInternalServerError)
			return
		}

		portStr, _, err := pool.GetSetting(ctx, smtpPortSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		port, _ := strconv.Atoi(portStr)

		encUsername, _, err := pool.GetSetting(ctx, smtpUsernameSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		username, err := crypto.DecryptIfNotEmpty(masterKey, encUsername)
		if err != nil {
			http.Error(w, fmt.Sprintf("decrypt smtp_username: %v", err), http.StatusInternalServerError)
			return
		}

		encFromAddress, _, err := pool.GetSetting(ctx, smtpFromAddressSettingKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		fromAddress, err := crypto.DecryptIfNotEmpty(masterKey, encFromAddress)
		if err != nil {
			http.Error(w, fmt.Sprintf("decrypt smtp_from_address: %v", err), http.StatusInternalServerError)
			return
		}

		encryption, err := resolveSMTPEncryption(ctx, pool)
		if err != nil {
			httperr.Internal(w, err)
			return
		}

		writeJSON(w, http.StatusOK, SMTPStatusResponse{
			Configured:  true,
			Host:        host,
			Port:        port,
			Username:    username,
			FromAddress: fromAddress,
			Encryption:  encryption,
		})
	}
}

// SMTPConfigureHandler validates and persists the SMTP configuration.
// masterKey must already be resolved (see ResolveMasterKey) - Password is
// encrypted with it before ever touching the database, unless empty (see
// SMTPConfigRequest's doc comment on unauthenticated relays).
func SMTPConfigureHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SMTPConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		req.Host = strings.TrimSpace(req.Host)
		req.Username = strings.TrimSpace(req.Username)
		req.FromAddress = strings.TrimSpace(req.FromAddress)
		req.Encryption = strings.TrimSpace(req.Encryption)

		if req.Host == "" || req.Port <= 0 || req.FromAddress == "" {
			http.Error(w, "host, port, and from_address are all required", http.StatusBadRequest)
			return
		}

		// Empty defaults to STARTTLS (see SMTPConfigRequest's doc comment);
		// anything else has to be one of the three known modes.
		if req.Encryption == "" {
			req.Encryption = SMTPEncryptionSTARTTLS
		}
		switch req.Encryption {
		case SMTPEncryptionNone, SMTPEncryptionSTARTTLS, SMTPEncryptionTLS:
			// ok
		default:
			http.Error(w, fmt.Sprintf("encryption must be one of %q, %q, %q", SMTPEncryptionNone, SMTPEncryptionSTARTTLS, SMTPEncryptionTLS), http.StatusBadRequest)
			return
		}

		encHost, err := crypto.Encrypt(masterKey, req.Host)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		encUsername, err := crypto.EncryptIfNotEmpty(masterKey, req.Username)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		encFromAddress, err := crypto.Encrypt(masterKey, req.FromAddress)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		ctx := r.Context()
		settings := map[string]string{
			smtpHostSettingKey:        encHost,
			smtpPortSettingKey:        strconv.Itoa(req.Port),
			smtpUsernameSettingKey:    encUsername,
			smtpFromAddressSettingKey: encFromAddress,
			smtpEncryptionSettingKey:  req.Encryption,
		}
		// Only overwrite the stored password when a new one was submitted.
		// An empty field means "keep the existing password" — identical to
		// how OIDCConfigureHandler treats ClientSecret. An admin who wants
		// to switch to an unauthenticated relay must delete the SMTP config
		// and re-add it without a password.
		if req.Password != "" {
			encryptedPassword, err := crypto.Encrypt(masterKey, req.Password)
			if err != nil {
				httperr.Internal(w, err)
				return
			}
			settings[smtpPasswordSettingKey] = encryptedPassword
		}
		for key, value := range settings {
			if err := pool.SetSetting(ctx, key, value); err != nil {
				httperr.Internal(w, err)
				return
			}
		}
		// The legacy boolean is never written again, but actively cleared
		// here so a later edit through this same handler does not leave a
		// stale, now-contradicting value behind for resolveSMTPEncryption
		// to fall back to (it only matters if smtpEncryptionSettingKey is
		// ever deleted independently, but cheap to keep both in sync).
		if err := pool.DeleteSetting(ctx, smtpUseTLSSettingKeyLegacy); err != nil {
			httperr.Internal(w, err)
			return
		}

		writeJSON(w, http.StatusOK, SMTPStatusResponse{
			Configured:  true,
			Host:        req.Host,
			Port:        req.Port,
			Username:    req.Username,
			FromAddress: req.FromAddress,
			Encryption:  req.Encryption,
		})
	}
}

// SMTPTestRequest is the body of POST /v1/admin/smtp/test.
// All fields mirror SMTPConfigRequest. To is the recipient address for the
// test message. The configuration is NOT persisted — the handler uses it
// only for the outbound connection so the operator can verify connectivity
// before committing via SMTPConfigureHandler.
//
// Password may be empty when a configuration is already saved and the admin
// has not re-entered the password (the frontend never receives the stored
// password for security reasons). SMTPTestHandler detects an empty Password
// and falls back to the stored encrypted password from core_settings, so
// testing an existing configuration works without re-entering the password —
// identical semantics to SMTPConfigureHandler's "leave empty to keep existing
// password" behaviour.
type SMTPTestRequest struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
	Encryption  string `json:"encryption"`
	To          string `json:"to"`
}

// SMTPTestHandler sends a single test message using the configuration
// supplied in the request body, without persisting anything. Returns 200
// on success, 400 for a missing/invalid field, or 502 if the outbound SMTP
// connection failed. Exposed via POST /v1/admin/smtp/test (super-admin only).
//
// pool and masterKey are required so the handler can fall back to the stored
// encrypted password when the request carries an empty Password field (the
// frontend never exposes the stored password to the browser).
func SMTPTestHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SMTPTestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		req.Host = strings.TrimSpace(req.Host)
		req.Username = strings.TrimSpace(req.Username)
		req.FromAddress = strings.TrimSpace(req.FromAddress)
		req.To = strings.TrimSpace(req.To)
		req.Encryption = strings.TrimSpace(req.Encryption)

		if req.Host == "" || req.Port <= 0 || req.FromAddress == "" || req.To == "" {
			http.Error(w, "host, port, from_address, and to are all required", http.StatusBadRequest)
			return
		}
		if req.Encryption == "" {
			req.Encryption = SMTPEncryptionSTARTTLS
		}
		switch req.Encryption {
		case SMTPEncryptionNone, SMTPEncryptionSTARTTLS, SMTPEncryptionTLS:
			// ok
		default:
			http.Error(w, fmt.Sprintf("encryption must be one of %q, %q, %q", SMTPEncryptionNone, SMTPEncryptionSTARTTLS, SMTPEncryptionTLS), http.StatusBadRequest)
			return
		}

		// When the request carries no password (the admin tests an existing
		// config without re-entering the password), fall back to the stored
		// encrypted password so the test does not fail with an auth error.
		password := req.Password
		if password == "" {
			if encPwd, exists, err := pool.GetSetting(r.Context(), smtpPasswordSettingKey); err == nil && exists && encPwd != "" {
				if dec, decErr := crypto.Decrypt(masterKey, encPwd); decErr == nil {
					password = dec
				}
			}
		}

		cfg := SMTPRuntimeConfig{
			Host:        req.Host,
			Port:        req.Port,
			Username:    req.Username,
			Password:    password,
			FromAddress: req.FromAddress,
			Encryption:  req.Encryption,
		}
		if err := SendTest(cfg, req.To); err != nil {
			http.Error(w, fmt.Sprintf("smtp test failed: %v", err), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// SendTest delivers a single test message over cfg to recipient to.
// Mirrors internal/mail's send() but lives here so the test handler can
// call it without creating a circular import (mail imports setup, not the
// other way around). No queue, no worker - just a synchronous dial-and-send
// so the operator gets immediate connection feedback.
func SendTest(cfg SMTPRuntimeConfig, to string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	subject := "ModuLab SMTP Test"
	body := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nThis is a test message sent from the ModuLab Setup Wizard to verify your SMTP configuration.\r\n",
		cfg.FromAddress, to, subject,
	))

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.Encryption == SMTPEncryptionNone {
		return smtp.SendMail(addr, auth, cfg.FromAddress, []string{to}, body)
	}

	var conn *smtp.Client
	if cfg.Encryption == SMTPEncryptionTLS {
		tlsConn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return fmt.Errorf("tls dial %s: %w", addr, err)
		}
		var clientErr error
		conn, clientErr = smtp.NewClient(tlsConn, cfg.Host)
		if clientErr != nil {
			if closeErr := tlsConn.Close(); closeErr != nil {
				log.Printf("setup: mail: close tls conn after client error: %v", closeErr)
			}
			return fmt.Errorf("smtp client: %w", clientErr)
		}
	} else {
		var err error
		conn, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("dial %s: %w", addr, err)
		}
		if err := conn.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("setup: mail: close conn after starttls error: %v", closeErr)
			}
			return fmt.Errorf("starttls: %w", err)
		}
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("setup: mail: close smtp conn: %v", err)
		}
	}()

	if auth != nil {
		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := conn.Mail(cfg.FromAddress); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := conn.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}
	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return conn.Quit()
}

// SMTPDeleteHandler clears the SMTP configuration entirely (all seven
// settings keys, including the legacy TLS flag), returning the instance to "not configured" - the
// counterpart to SMTPConfigureHandler an admin needs to actually remove a
// relay rather than only ever being able to overwrite it with different
// values. After this, SMTPConfigured reports false again and
// ResolveSMTPConfig fails the same "has not been configured yet" way it
// does on a fresh install, so mail.RunWorker's existing "not configured"
// handling (log and drop) applies without any further changes there.
func SMTPDeleteHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		for _, key := range []string{
			smtpHostSettingKey,
			smtpPortSettingKey,
			smtpUsernameSettingKey,
			smtpPasswordSettingKey,
			smtpFromAddressSettingKey,
			smtpEncryptionSettingKey,
			smtpUseTLSSettingKeyLegacy,
		} {
			if err := pool.DeleteSetting(ctx, key); err != nil {
				httperr.Internal(w, err)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
