package db

import (
	"context"
	"fmt"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// ---- News feeds -------------------------------------------------------------

// FeedRow is one row of the news_feeds table.
type FeedRow struct {
	ID        int
	URL       string
	Label     string
	CreatedAt time.Time
}

// FeedWithSub pairs a feed row with the requesting user's current
// subscription state, returned by ListFeedsForUser.
type FeedWithSub struct {
	ID        int
	URL       string
	Label     string
	Enabled   bool
	CreatedAt time.Time
}

// EnsureNewsSchema creates the news_feeds and user_feed_subscriptions tables
// if they do not exist yet. Called from EnsureCoreSchema, after the users
// table, so the foreign key on user_feed_subscriptions.user_id resolves.
func (p *Pool) EnsureNewsSchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS news_feeds (
			id         SERIAL PRIMARY KEY,
			url        TEXT NOT NULL,
			label      TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure news_feeds: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_feed_subscriptions (
			user_id TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			feed_id INTEGER NOT NULL REFERENCES news_feeds(id) ON DELETE CASCADE,
			enabled BOOLEAN NOT NULL DEFAULT false,
			PRIMARY KEY (user_id, feed_id)
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_feed_subscriptions: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_news_preferences (
			user_id           TEXT    PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			home_article_count INTEGER NOT NULL DEFAULT 5,
			show_images       BOOLEAN NOT NULL DEFAULT true
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_news_preferences: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_search_preferences (
			user_id    TEXT    PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			safesearch INTEGER NOT NULL DEFAULT 0,
			language   TEXT    NOT NULL DEFAULT 'all'
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_search_preferences: %w", err)
	}
	return nil
}

// NewsPrefs holds a user's news-display preferences.
type NewsPrefs struct {
	HomeArticleCount int  `json:"home_article_count"`
	ShowImages       bool `json:"show_images"`
}

// GetNewsPrefs returns the stored preferences for userID, or the defaults
// (5 articles, images on) if no row exists yet.
func (p *Pool) GetNewsPrefs(ctx context.Context, userID string) (NewsPrefs, error) {
	var prefs NewsPrefs
	err := p.QueryRow(ctx, `
		SELECT home_article_count, show_images
		FROM   user_news_preferences
		WHERE  user_id = $1
	`, userID).Scan(&prefs.HomeArticleCount, &prefs.ShowImages)
	if err != nil {
		// No row yet → return defaults.
		return NewsPrefs{HomeArticleCount: 5, ShowImages: true}, nil
	}
	return prefs, nil
}

// SetNewsPrefs upserts the preferences for userID.
func (p *Pool) SetNewsPrefs(ctx context.Context, userID string, prefs NewsPrefs) error {
	if prefs.HomeArticleCount < 1 {
		prefs.HomeArticleCount = 1
	}
	if prefs.HomeArticleCount > 50 {
		prefs.HomeArticleCount = 50
	}
	_, err := p.Exec(ctx, `
		INSERT INTO user_news_preferences (user_id, home_article_count, show_images)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		  SET home_article_count = EXCLUDED.home_article_count,
		      show_images        = EXCLUDED.show_images
	`, userID, prefs.HomeArticleCount, prefs.ShowImages)
	return err
}

// ListFeeds returns every feed row, sorted alphabetically by label. Used by
// the admin CRUD and by the news aggregator to look up feed URLs. url is
// stored encrypted (see CreateFeed's doc comment) and decrypted here so
// every caller keeps seeing plaintext, same as before this field was
// encrypted.
func (p *Pool) ListFeeds(ctx context.Context) ([]FeedRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, url, label, created_at FROM news_feeds ORDER BY lower(label) ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list feeds: %w", err)
	}
	defer rows.Close()
	var out []FeedRow
	for rows.Next() {
		var f FeedRow
		if err := rows.Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan feed: %w", err)
		}
		if f.URL, err = crypto.DecryptIfNotEmpty(p.masterKey, f.URL); err != nil {
			return nil, fmt.Errorf("db: decrypt feed %d url: %w", f.ID, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFeed inserts a new feed and returns the created row (with its
// server-assigned id and created_at). feedURL is a PII-adjacent field (it
// can reveal a user's/org's reading habits and, for private feeds, internal
// infrastructure hostnames) and is stored encrypted at rest via
// crypto.Encrypt, matching the project's PII/URL encryption convention
// already used for SearXNG's URL and SMTP host - see MigrateToEncryptedStorage
// for the one-time backfill of rows created before this change.
func (p *Pool) CreateFeed(ctx context.Context, feedURL, label string) (FeedRow, error) {
	encURL, err := crypto.Encrypt(p.masterKey, feedURL)
	if err != nil {
		return FeedRow{}, fmt.Errorf("db: encrypt feed url: %w", err)
	}
	var f FeedRow
	err = p.QueryRow(ctx, `
		INSERT INTO news_feeds (url, label) VALUES ($1, $2)
		RETURNING id, url, label, created_at
	`, encURL, label).Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt)
	if err != nil {
		return FeedRow{}, fmt.Errorf("db: create feed: %w", err)
	}
	f.URL = feedURL
	return f, nil
}

// UpdateFeed sets url and label for the given feed id. Returns found = false
// (not an error) when no such id exists, so the handler can return 404
// without a separate existence check. url is encrypted before storage, same
// as CreateFeed.
func (p *Pool) UpdateFeed(ctx context.Context, id int, feedURL, label string) (bool, error) {
	encURL, err := crypto.Encrypt(p.masterKey, feedURL)
	if err != nil {
		return false, fmt.Errorf("db: encrypt feed url: %w", err)
	}
	tag, err := p.Exec(ctx, `
		UPDATE news_feeds SET url = $1, label = $2 WHERE id = $3
	`, encURL, label, id)
	if err != nil {
		return false, fmt.Errorf("db: update feed %d: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteFeed removes the feed row. ON DELETE CASCADE in
// user_feed_subscriptions handles the child rows automatically. Returns
// found = false when no such id exists.
func (p *Pool) DeleteFeed(ctx context.Context, id int) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM news_feeds WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("db: delete feed %d: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListFeedsForUser returns every feed paired with whether userID has it
// enabled. A missing subscription row is treated as enabled = false (the
// default for newly added feeds, per the agreed spec: new feeds are opt-in).
func (p *Pool) ListFeedsForUser(ctx context.Context, userID string) ([]FeedWithSub, error) {
	rows, err := p.Query(ctx, `
		SELECT f.id, f.url, f.label, f.created_at,
		       COALESCE(s.enabled, false) AS enabled
		FROM   news_feeds f
		LEFT   JOIN user_feed_subscriptions s
		       ON s.feed_id = f.id AND s.user_id = $1
		ORDER  BY lower(f.label) ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list feeds for user: %w", err)
	}
	defer rows.Close()
	var out []FeedWithSub
	for rows.Next() {
		var f FeedWithSub
		if err := rows.Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt, &f.Enabled); err != nil {
			return nil, fmt.Errorf("db: scan feed with sub: %w", err)
		}
		if f.URL, err = crypto.DecryptIfNotEmpty(p.masterKey, f.URL); err != nil {
			return nil, fmt.Errorf("db: decrypt feed %d url: %w", f.ID, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFeedSubscription upserts the user's enabled/disabled preference for a
// single feed. A feedID that does not exist causes a foreign-key violation
// (returned as an error); callers should surface this as 404.
func (p *Pool) SetFeedSubscription(ctx context.Context, userID string, feedID int, enabled bool) error {
	_, err := p.Exec(ctx, `
		INSERT INTO user_feed_subscriptions (user_id, feed_id, enabled)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, feed_id) DO UPDATE SET enabled = EXCLUDED.enabled
	`, userID, feedID, enabled)
	if err != nil {
		return fmt.Errorf("db: set feed subscription: %w", err)
	}
	return nil
}

// EnabledFeedsForUser returns the feed rows the user has explicitly enabled,
// used by the news aggregator to decide which feeds to fetch.
func (p *Pool) EnabledFeedsForUser(ctx context.Context, userID string) ([]FeedRow, error) {
	rows, err := p.Query(ctx, `
		SELECT f.id, f.url, f.label, f.created_at
		FROM   news_feeds f
		JOIN   user_feed_subscriptions s ON s.feed_id = f.id
		WHERE  s.user_id = $1 AND s.enabled = true
		ORDER  BY f.created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: enabled feeds for user: %w", err)
	}
	defer rows.Close()
	var out []FeedRow
	for rows.Next() {
		var f FeedRow
		if err := rows.Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan enabled feed: %w", err)
		}
		if f.URL, err = crypto.DecryptIfNotEmpty(p.masterKey, f.URL); err != nil {
			return nil, fmt.Errorf("db: decrypt feed %d url: %w", f.ID, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
