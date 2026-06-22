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
// plain SMTP with optional STARTTLS/implicit-TLS and PLAIN auth; nothing
// here needs HTML rendering, attachments, or provider-specific APIs.
func send(cfg setup.SMTPRuntimeConfig, msg Message) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	body := buildMessage(cfg.FromAddress, msg)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.Encryption == setup.SMTPEncryptionNone {
		// smtp.SendMail covers dial, optional auth, and the full
		// MAIL/RCPT/DATA sequence in one call. Fine for a same-LAN relay
		// that never needed an encrypted hop in the first place (the
		// common case spec section 3.5 describes - Core and a self-hosted
		// Postfix/Mailcow on the same trusted network).
		return smtp.SendMail(addr, auth, cfg.FromAddress, []string{msg.To}, body)
	}

	var conn *smtp.Client
	if cfg.Encryption == setup.SMTPEncryptionTLS {
		// Implicit TLS ("SSL", commonly port 465): the relay expects TLS
		// from the very first byte, unlike STARTTLS below which starts
		// plaintext and upgrades mid-conversation. tls.Dial does the full
		// handshake before smtp.NewClient ever speaks the SMTP protocol
		// over it.
		tlsConn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return fmt.Errorf("tls dial %s: %w", addr, err)
		}
		conn, err = smtp.NewClient(tlsConn, cfg.Host)
		if err != nil {
			tlsConn.Close()
			return fmt.Errorf("smtp client: %w", err)
		}
	} else {
		// STARTTLS path (commonly port 587): net/smtp's SendMail has no
		// option to upgrade the connection, so the handshake is driven
		// manually here - dial in plaintext, then upgrade before
		// authenticating.
		var err error
		conn, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("dial %s: %w", addr, err)
		}
		if err := conn.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			conn.Close()
			return fmt.Errorf("starttls: %w", err)
		}
	}
	defer conn.Close()

	// Shared by both the implicit-TLS and STARTTLS paths from here on -
	// once the connection is encrypted, auth and the MAIL/RCPT/DATA
	// sequence are identical either way.
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
