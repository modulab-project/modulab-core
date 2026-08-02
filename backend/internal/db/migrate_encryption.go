package db

import (
	"context"
	"fmt"
	"strconv"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// encryptionVersionKey is the core_settings key that records whether the
// one-time plaintext→encrypted storage migration has been completed for
// this instance. Absent = not yet run; "1" = done.
const encryptionVersionKey = "core_encryption_version"

// MigrateToEncryptedStorage is a one-time startup migration that encrypts
// any plaintext PII that existed in the database before the encrypt-
// everything feature landed. It is safe to call on every boot: the
// core_encryption_version flag in core_settings makes each step a no-op
// once it has run successfully. The flag is a numeric string so later steps
// (e.g. version "2" below) can be added without re-running earlier ones on
// instances that already completed them.
//
// Fields migrated at version 1:
//   - users.email, users.name
//   - core_settings: smtp_host, smtp_username, smtp_from_address,
//     oidc_issuer_url, oidc_client_id
//     (dns_challenge_provider was migrated here too until the DNS-challenge
//     feature was removed entirely - see migration 0005)
//
// Fields migrated at version 2:
//   - news_feeds.url (CreateFeed/UpdateFeed started encrypting new rows
//     directly; this backfills rows created before that change)
//
// The _enc variants (smtp_password_enc, oidc_client_secret_enc) were
// already encrypted before this feature landed and are left untouched.
func (p *Pool) MigrateToEncryptedStorage(ctx context.Context) error {
	v, exists, err := p.GetSetting(ctx, encryptionVersionKey)
	if err != nil {
		return fmt.Errorf("db: migration check: %w", err)
	}
	version := 0
	if exists {
		version, err = strconv.Atoi(v)
		if err != nil {
			// A corrupt version flag must not silently fall back to 0 - that
			// would make MigrateToEncryptedStorage think nothing has run yet
			// and re-run migrateEncryptionV1/V2 against data that may already
			// be encrypted, risking double-encryption. Fail closed instead;
			// main.go treats this error as fatal at startup (log.Fatalf), so
			// an operator has to fix the core_settings row by hand rather
			// than the migration silently repeating.
			return fmt.Errorf("db: migration check: corrupt %s value %q: %w", encryptionVersionKey, v, err)
		}
	}
	if version >= 2 {
		return nil // already done
	}

	if version < 1 {
		if err := p.migrateEncryptionV1(ctx); err != nil {
			return err
		}
	}
	if version < 2 {
		if err := p.migrateEncryptionV2NewsFeeds(ctx); err != nil {
			return err
		}
	}

	if err := p.SetSetting(ctx, encryptionVersionKey, "2"); err != nil {
		return fmt.Errorf("db: migration set version flag: %w", err)
	}
	return nil
}

// migrateEncryptionV2NewsFeeds backfills news_feeds.url for rows written
// before CreateFeed/UpdateFeed started encrypting it. Detects already-
// encrypted rows by attempting a decrypt first: crypto.Encrypt's output is
// never valid as a bare http(s) URL, so a successful decrypt means "already
// migrated, skip" and a decrypt failure means "still plaintext, encrypt it".
func (p *Pool) migrateEncryptionV2NewsFeeds(ctx context.Context) error {
	rows, err := p.Query(ctx, `SELECT id, url FROM news_feeds`)
	if err != nil {
		return fmt.Errorf("db: migration list news_feeds: %w", err)
	}
	type feedPlain struct {
		id  int
		url string
	}
	var feeds []feedPlain
	for rows.Next() {
		var f feedPlain
		if err := rows.Scan(&f.id, &f.url); err != nil {
			rows.Close()
			return fmt.Errorf("db: migration scan news_feed: %w", err)
		}
		feeds = append(feeds, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("db: migration rows: %w", err)
	}

	for _, f := range feeds {
		if f.url == "" {
			continue
		}
		if _, err := crypto.Decrypt(p.masterKey, f.url); err == nil {
			continue // already encrypted, skip
		}
		enc, err := crypto.Encrypt(p.masterKey, f.url)
		if err != nil {
			return fmt.Errorf("db: migration encrypt news_feed %d url: %w", f.id, err)
		}
		if _, err := p.Exec(ctx, `UPDATE news_feeds SET url=$1 WHERE id=$2`, enc, f.id); err != nil {
			return fmt.Errorf("db: migration update news_feed %d: %w", f.id, err)
		}
	}
	return nil
}

// migrateEncryptionV1 is the original (pre-versioning) migration body,
// unchanged in behavior from before version tracking was introduced.
func (p *Pool) migrateEncryptionV1(ctx context.Context) error {
	// Migrate users table: read id/email/name, encrypt, write back.
	rows, err := p.Query(ctx, `SELECT id, email, name FROM users`)
	if err != nil {
		return fmt.Errorf("db: migration list users: %w", err)
	}
	type userPlain struct{ id, email, name string }
	var users []userPlain
	for rows.Next() {
		var u userPlain
		if err := rows.Scan(&u.id, &u.email, &u.name); err != nil {
			rows.Close()
			return fmt.Errorf("db: migration scan user: %w", err)
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("db: migration rows: %w", err)
	}

	for _, u := range users {
		encEmail, err := crypto.EncryptIfNotEmpty(p.masterKey, u.email)
		if err != nil {
			return fmt.Errorf("db: migration encrypt email for %q: %w", u.id, err)
		}
		encName, err := crypto.EncryptIfNotEmpty(p.masterKey, u.name)
		if err != nil {
			return fmt.Errorf("db: migration encrypt name for %q: %w", u.id, err)
		}
		if _, err := p.Exec(ctx, `UPDATE users SET email=$1, name=$2 WHERE id=$3`, encEmail, encName, u.id); err != nil {
			return fmt.Errorf("db: migration update user %q: %w", u.id, err)
		}
	}

	// Migrate core_settings: plaintext configuration fields.
	settingsToMigrate := []string{
		"smtp_host", "smtp_username", "smtp_from_address",
		"oidc_issuer_url", "oidc_client_id",
	}
	for _, key := range settingsToMigrate {
		val, exists, err := p.GetSetting(ctx, key)
		if err != nil {
			return fmt.Errorf("db: migration get setting %q: %w", key, err)
		}
		if !exists || val == "" {
			continue
		}
		enc, err := crypto.Encrypt(p.masterKey, val)
		if err != nil {
			return fmt.Errorf("db: migration encrypt setting %q: %w", key, err)
		}
		if err := p.SetSetting(ctx, key, enc); err != nil {
			return fmt.Errorf("db: migration set setting %q: %w", key, err)
		}
	}

	// Version flag is set by the MigrateToEncryptedStorage wrapper after all
	// applicable steps (this one and any later ones) have succeeded, not
	// here - see its doc comment.
	return nil
}
