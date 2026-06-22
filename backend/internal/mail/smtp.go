package mail

import (
	"crypto/tls"
	"fmt"
	"net/smtp"

	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// send delivers msg over cfg. Plain net/smtp - no third-party mail
// library - since spec section 3.5 only asks for compatibility with
// self-hosted SMTP relays (Postfix, Mailcow, Stalwart), all of which speak
// plain SMTP with optional STARTTLS and PLAIN auth; nothing here needs
// HTML rendering, attachments, or provider-specific APIs.
func send(cfg setup.SMTPRuntimeConfig, msg Message) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	body := buildMessage(cfg.FromAddress, msg)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if !cfg.UseTLS {
		// No STARTTLS requested - smtp.SendMail covers dial, optional auth,
		// and the full MAIL/RCPT/DATA sequence in one call. Fine for a
		// same-LAN relay that never needed an encrypted hop in the first
		// place (the common case spec section 3.5 describes - Core and a
		// self-hosted Postfix/Mailcow on the same trusted network).
		return smtp.SendMail(addr, auth, cfg.FromAddress, []string{msg.To}, body)
	}

	// STARTTLS path: net/smtp's SendMail has no option to upgrade the
	// connection, so the handshake is driven manually here - dial in
	// plaintext, upgrade, authenticate, then the same MAIL/RCPT/DATA
	// sequence SendMail would otherwise do internally.
	conn, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if auth != nil {
		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := conn.Mail(cfg.FromAddress); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := conn.Rcpt(msg.To); err != nil {
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

// buildMessage renders msg as a minimal RFC 5322 message - plain text
// only, one fixed header set. Sufficient for the short, single-paragraph
// notifications templates.go produces; revisit if a future message
// actually needs HTML or attachments.
func buildMessage(from string, msg Message) []byte {
	return []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		from, msg.To, msg.Subject, msg.Body,
	))
}
