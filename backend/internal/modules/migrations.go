package modules

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// runModuleMigrations provisions a Postgres schema for the module and executes
// all SQL files found in migrationsDir (migrations/*.sql), ordered by filename.
//
// What it does:
//  1. CREATE SCHEMA IF NOT EXISTS module_{name}
//  2. CREATE ROLE module_{name}_role (for future RLS use, if not exists)
//  3. GRANT USAGE ON SCHEMA to that role
//  4. Execute each *.sql file in migrationsDir in lexicographic order,
//     wrapping all files in a single transaction (all-or-nothing).
//
// migrationsDir is the path on disk where the module's migrations/ directory
// was extracted. If the directory does not exist or is empty, the function
// returns nil (many modules may have no migrations).
//
// The module name must satisfy the module naming convention (modulab-mod-*
// or admin-whitelisted), which the installer already verified before calling
// us. We sanitise it again here because the schema name goes directly into
// SQL identifiers.
func runModuleMigrations(ctx context.Context, d Deps, moduleName, migrationsDir string) error {
	schemaName, roleName, err := moduleIdentifiers(moduleName)
	if err != nil {
		return err
	}

	// Collect SQL files.
	files, err := sqlFilesInDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("modules: migrations %q: scan dir: %w", moduleName, err)
	}

	// Always provision the schema + role, even when there are no migration
	// files. A module might create its tables entirely from Go or Deno code
	// and still need the schema to exist.
	if err := provisionSchema(ctx, d, schemaName, roleName); err != nil {
		return fmt.Errorf("modules: migrations %q: provision schema: %w", moduleName, err)
	}

	if len(files) == 0 {
		log.Printf("modules: migrations %q: no SQL files in %s — schema provisioned, nothing to run", moduleName, migrationsDir)
		return nil
	}

	log.Printf("modules: migrations %q: running %d file(s) in schema %q", moduleName, len(files), schemaName)

	// Execute all migration files inside a single transaction so a partial
	// failure leaves the schema in a clean state.
	tx, err := d.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("modules: migrations %q: begin tx: %w", moduleName, err)
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	// Set search_path for this transaction so module SQL can use unqualified
	// table names and they land in the right schema.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL search_path TO %s, public", quoteIdent(schemaName))); err != nil {
		return fmt.Errorf("modules: migrations %q: set search_path: %w", moduleName, err)
	}

	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("modules: migrations %q: read %s: %w", moduleName, filepath.Base(f), err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("modules: migrations %q: exec %s: %w", moduleName, filepath.Base(f), err)
		}
		log.Printf("modules: migrations %q: applied %s", moduleName, filepath.Base(f))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("modules: migrations %q: commit: %w", moduleName, err)
	}
	tx = nil // prevent deferred rollback after successful commit

	log.Printf("modules: migrations %q: all migrations committed", moduleName)
	return nil
}

// runModuleUpdateMigrations runs only the migration files that are new in the
// updated version. It compares filenames in newMigrationsDir against the list
// of already-applied files stored in the module_migrations tracking table, and
// runs only the difference in order.
//
// If the tracking table has no rows for this module (first-ever update, or the
// table was absent in the old version), it falls back to running all files.
func runModuleUpdateMigrations(ctx context.Context, d Deps, moduleName, newMigrationsDir string) error {
	schemaName, roleName, err := moduleIdentifiers(moduleName)
	if err != nil {
		return err
	}

	allFiles, err := sqlFilesInDir(newMigrationsDir)
	if err != nil {
		return fmt.Errorf("modules: update migrations %q: scan dir: %w", moduleName, err)
	}

	// Ensure schema + role exist (idempotent).
	if err := provisionSchema(ctx, d, schemaName, roleName); err != nil {
		return fmt.Errorf("modules: update migrations %q: provision schema: %w", moduleName, err)
	}

	if len(allFiles) == 0 {
		return nil
	}

	// Determine which files have already been applied.
	applied, err := appliedMigrations(ctx, d, moduleName)
	if err != nil {
		// If the tracking table doesn't exist yet (old Core version), run all.
		log.Printf("modules: update migrations %q: could not read applied list, running all: %v", moduleName, err)
		applied = map[string]bool{}
	}

	var pending []string
	for _, f := range allFiles {
		if !applied[filepath.Base(f)] {
			pending = append(pending, f)
		}
	}

	if len(pending) == 0 {
		log.Printf("modules: update migrations %q: no new migrations to run", moduleName)
		return nil
	}

	log.Printf("modules: update migrations %q: running %d new file(s)", moduleName, len(pending))

	tx, err := d.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("modules: update migrations %q: begin tx: %w", moduleName, err)
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL search_path TO %s, public", quoteIdent(schemaName))); err != nil {
		return fmt.Errorf("modules: update migrations %q: set search_path: %w", moduleName, err)
	}

	for _, f := range pending {
		sql, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("modules: update migrations %q: read %s: %w", moduleName, filepath.Base(f), err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("modules: update migrations %q: exec %s: %w", moduleName, filepath.Base(f), err)
		}
		// Record the migration as applied (inside the same transaction).
		if _, err := tx.Exec(ctx, `
			INSERT INTO module_migrations (module_name, filename, applied_at)
			VALUES ($1, $2, now())
			ON CONFLICT (module_name, filename) DO NOTHING
		`, moduleName, filepath.Base(f)); err != nil {
			return fmt.Errorf("modules: update migrations %q: record %s: %w", moduleName, filepath.Base(f), err)
		}
		log.Printf("modules: update migrations %q: applied %s", moduleName, filepath.Base(f))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("modules: update migrations %q: commit: %w", moduleName, err)
	}
	tx = nil

	log.Printf("modules: update migrations %q: done", moduleName)
	return nil
}

// dropModuleSchema drops the module's Postgres schema and role.
// Not called yet - written ahead of the /v1/modules/{name}/purge endpoint
// mentioned in uninstaller.go's doc comment (data purge is explicit-only,
// never part of standard uninstall, which preserves data per spec section
// 4.8). Kept in place rather than deleted so that endpoint doesn't need to
// rewrite this logic from scratch; silenced here rather than left to trip
// the unused-function check until it's wired up.
//
//nolint:unused // reserved for the not-yet-implemented purge endpoint
func dropModuleSchema(ctx context.Context, d Deps, moduleName string) error {
	schemaName, roleName, err := moduleIdentifiers(moduleName)
	if err != nil {
		return err
	}

	// CASCADE drops all tables, sequences, and other objects in the schema.
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaName))); err != nil {
		return fmt.Errorf("modules: drop schema %q: %w", schemaName, err)
	}
	// Remove migration tracking rows.
	if _, err := d.DB.Exec(ctx, `DELETE FROM module_migrations WHERE module_name = $1`, moduleName); err != nil {
		log.Printf("modules: drop schema %q: could not remove migration tracking rows: %v", moduleName, err)
	}
	// Drop the role last (after schema is gone, otherwise role may still own objects).
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", quoteIdent(roleName))); err != nil {
		log.Printf("modules: drop schema %q: could not drop role %s: %v", schemaName, roleName, err)
	}

	log.Printf("modules: dropped schema %q and role %q", schemaName, roleName)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// safeIdentRe matches only characters that are safe as Postgres identifiers.
// Module names like "modulab-mod-rezepte" are converted to underscores.
var safeIdentRe = regexp.MustCompile(`[^a-z0-9_]`)

// moduleIdentifiers derives the Postgres schema name and role name from the
// module name. Hyphens are converted to underscores; all other non-alphanum
// characters are rejected.
func moduleIdentifiers(moduleName string) (schemaName, roleName string, err error) {
	if moduleName == "" {
		return "", "", fmt.Errorf("modules: empty module name")
	}
	safe := safeIdentRe.ReplaceAllString(strings.ToLower(moduleName), "_")
	// Ensure it starts with a letter (Postgres identifier rule).
	if len(safe) == 0 || (safe[0] >= '0' && safe[0] <= '9') {
		return "", "", fmt.Errorf("modules: module name %q produces invalid identifier %q", moduleName, safe)
	}
	schemaName = "module_" + safe
	roleName = "module_" + safe + "_role"
	return schemaName, roleName, nil
}

// quoteIdent double-quotes name for use as a Postgres identifier (schema or
// role name) in a raw SQL string built via fmt.Sprintf. moduleIdentifiers
// already restricts the underlying value to [a-z_][a-z0-9_]* via
// safeIdentRe, so this is defense-in-depth rather than the only thing
// standing between us and injection - but building identifiers with bare
// fmt.Sprintf is exactly the kind of thing that becomes a real bug the
// moment safeIdentRe is ever loosened, so every identifier interpolated into
// SQL below goes through this rather than being trusted as pre-sanitised.
func quoteIdent(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// provisionSchema creates the Postgres schema and role for a module if they
// do not already exist, and creates the migration tracking table if absent.
func provisionSchema(ctx context.Context, d Deps, schemaName, roleName string) error {
	// Create schema.
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quoteIdent(schemaName))); err != nil {
		return fmt.Errorf("create schema %s: %w", schemaName, err)
	}
	// Create role (no login, no superuser).
	// IF NOT EXISTS is Postgres 9.5+ — safe here. roleName appears twice: once
	// as a quoted string literal (pg_roles.rolname comparison - not an
	// identifier, left as a plain %s since safeIdentRe already guarantees no
	// quote characters can appear in it) and once as the identifier being
	// created (quoted via quoteIdent).
	if _, err := d.DB.Exec(ctx, fmt.Sprintf(`
		DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN
				CREATE ROLE %s NOLOGIN;
			END IF;
		END $$`, roleName, quoteIdent(roleName)),
	); err != nil {
		return fmt.Errorf("create role %s: %w", roleName, err)
	}
	// Grant usage on the schema to the role.
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", quoteIdent(schemaName), quoteIdent(roleName))); err != nil {
		return fmt.Errorf("grant usage on %s to %s: %w", schemaName, roleName, err)
	}
	// Migration tracking table (in the public schema, owned by Core's superuser).
	if _, err := d.DB.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS module_migrations (
			module_name TEXT        NOT NULL,
			filename    TEXT        NOT NULL,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (module_name, filename)
		)
	`); err != nil {
		return fmt.Errorf("create module_migrations table: %w", err)
	}
	return nil
}

// sqlFilesInDir returns all *.sql files in dir, sorted lexicographically.
// Returns (nil, nil) when dir does not exist (module has no migrations).
func sqlFilesInDir(dir string) ([]string, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// appliedMigrations returns the set of filenames already recorded in
// module_migrations for the given module.
func appliedMigrations(ctx context.Context, d Deps, moduleName string) (map[string]bool, error) {
	rows, err := d.DB.Query(ctx, `
		SELECT filename FROM module_migrations WHERE module_name = $1
	`, moduleName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}
