package modules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// EnsureModuleDBRole provisions (or, for a module installed before this
// feature existed, upgrades) moduleName's dedicated Postgres LOGIN role and
// returns its password, ready to use as WorkerOptions.DBRolePassword.
// Idempotent - safe to call every time a worker is about to start,
// including for a module whose role/password already exist (see
// provisionSchema's reuse-if-present logic).
//
// Exported for cmd/core/main.go's startup worker-restart loop: at boot,
// every already-`ModuleStatusActive` module needs its role/password
// verified (and, for anything installed by a Core version predating this
// feature, actually created) BEFORE WorkerPool.Start is called for it -
// otherwise buildWorker's empty-password check rejects the start outright,
// and a module that worked fine yesterday would refuse to come back after
// a plain Core restart, with no Install/Update having happened at all.
// Install/Update (runModuleMigrations/runModuleUpdateMigrations below)
// already call provisionSchema directly as part of running migrations;
// this wrapper exists for the one caller that needs the role ensured
// without also wanting to (re-)run migration SQL.
func EnsureModuleDBRole(ctx context.Context, d Deps, moduleName string) (string, error) {
	schemaName, roleName, err := moduleIdentifiers(moduleName)
	if err != nil {
		return "", err
	}
	return provisionSchema(ctx, d, moduleName, schemaName, roleName)
}

// runModuleMigrations provisions a Postgres schema and dedicated LOGIN role
// for the module, then executes all SQL files found in migrationsDir
// (migrations/*.sql, ordered by filename) using a connection authenticated
// as that role - not Core's own superuser connection (d.DB).
//
// What it does:
//  1. CREATE SCHEMA IF NOT EXISTS module_{name}
//  2. provisionSchema: create/upgrade module_{name}_role to a LOGIN role
//     with its own random password, scoped to its own schema only (see
//     provisionSchema's doc comment)
//  3. Open a second connection authenticated as module_{name}_role
//  4. Execute each *.sql file in migrationsDir in lexicographic order over
//     that connection, wrapping all files in a single transaction
//     (all-or-nothing)
//
// migrationsDir is the path on disk where the module's migrations/ directory
// was extracted. If the directory does not exist or is empty, the function
// returns nil (many modules may have no migrations).
//
// moduleName comes from the manifest (already checked non-empty by
// parseManifest and matched against the registry entry by Install/Update).
// We sanitise it again here regardless, because the schema name goes
// directly into SQL identifiers.
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
	password, err := provisionSchema(ctx, d, moduleName, schemaName, roleName)
	if err != nil {
		return fmt.Errorf("modules: migrations %q: provision schema: %w", moduleName, err)
	}

	if len(files) == 0 {
		log.Printf("modules: migrations %q: no SQL files in %s — schema provisioned, nothing to run", moduleName, migrationsDir)
		return nil
	}

	log.Printf("modules: migrations %q: running %d file(s) in schema %q", moduleName, len(files), schemaName)

	moduleConn, err := connectAsModuleRole(ctx, d, roleName, password)
	if err != nil {
		return fmt.Errorf("modules: migrations %q: connect as %s: %w", moduleName, roleName, err)
	}
	defer func() {
		if err := moduleConn.Close(ctx); err != nil {
			log.Printf("modules: migrations %q: close module role connection: %v", moduleName, err)
		}
	}()

	// Execute all migration files inside a single transaction so a partial
	// failure leaves the schema in a clean state. Runs as the module's own
	// role (module_{name}_role), not Core's superuser (d.DB) - the role's
	// GRANTs (see provisionSchema) are what actually confine this SQL to
	// its own schema now, not just the search_path set below. A migration
	// file that tried DROP TABLE public.users or GRANT ALL ON SCHEMA
	// public simply fails with a permissions error instead of succeeding.
	tx, err := moduleConn.Begin(ctx)
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
	password, err := provisionSchema(ctx, d, moduleName, schemaName, roleName)
	if err != nil {
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

	moduleConn, err := connectAsModuleRole(ctx, d, roleName, password)
	if err != nil {
		return fmt.Errorf("modules: update migrations %q: connect as %s: %w", moduleName, roleName, err)
	}
	defer func() {
		if err := moduleConn.Close(ctx); err != nil {
			log.Printf("modules: update migrations %q: close module role connection: %v", moduleName, err)
		}
	}()

	// Runs as the module's own role, same reasoning as runModuleMigrations
	// above - the tracking INSERT below is deliberately NOT part of this
	// transaction (see the comment above module_migrations' definition in
	// provisionSchema): it happens afterward, over d.DB, because it is
	// Core's own bookkeeping in the public schema, not module data, and the
	// module role has no grants there.
	tx, err := moduleConn.Begin(ctx)
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
		log.Printf("modules: update migrations %q: applied %s", moduleName, filepath.Base(f))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("modules: update migrations %q: commit: %w", moduleName, err)
	}
	tx = nil

	// Record every file just applied as applied, over Core's own
	// connection (module_migrations lives in public, owned by Core - see
	// provisionSchema). Best-effort per file: if recording one fails, the
	// migration itself already committed successfully above, so we log
	// and continue rather than report the whole update as failed - the
	// worst case is that file gets re-attempted (and no-ops, since
	// module SQL is expected to be idempotent, e.g. CREATE TABLE IF NOT
	// EXISTS) on the next update.
	for _, f := range pending {
		if _, err := d.DB.Exec(ctx, `
			INSERT INTO module_migrations (module_name, filename, applied_at)
			VALUES ($1, $2, now())
			ON CONFLICT (module_name, filename) DO NOTHING
		`, moduleName, filepath.Base(f)); err != nil {
			log.Printf("modules: update migrations %q: record %s applied: %v", moduleName, filepath.Base(f), err)
		}
	}

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
	// Clear the stored role password too - the role itself is gone, so a
	// leftover encrypted password lying around in installed_modules would
	// be meaningless (and, if the same module name were ever reinstalled,
	// stale: provisionSchema would otherwise find "a password on file" for
	// a role that no longer exists and skip generating a fresh one - see
	// provisionSchema's !hasPassword branch).
	if err := d.DB.ClearModuleDBRolePassword(ctx, moduleName); err != nil {
		log.Printf("modules: drop schema %q: could not clear stored role password: %v", schemaName, err)
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

// provisionSchema creates the Postgres schema for a module if it does not
// already exist, ensures the module has its own Postgres LOGIN role (never
// Core's own credentials - see this function's longer doc comment below),
// grants that role exactly the rights it needs inside its own schema and
// nothing outside it, and creates the migration tracking table if absent.
// Returns the role's password (existing, if this module has one on file
// already, or freshly generated otherwise) so callers can open a connection
// authenticated as the role (see connectAsModuleRole).
//
// Why a real LOGIN role at all: before this, every module - Tier 2/3 Deno
// workers via WorkerPool, and the migration SQL below - connected to
// Postgres using Core's own DB credentials, relying on a `search_path`
// setting to keep them inside their own schema. search_path only changes
// how *unqualified* names resolve; it grants no access and blocks none. Any
// module SQL (a migration file from a module ZIP, or - before deno.go's own
// switch to this same role - a compromised Deno worker) could simply
// schema-qualify its way into `public.users`, `core_settings`, or another
// module's schema, because the connection itself had Core's own superuser
// rights the whole time. A dedicated, minimally-privileged role turns
// "confined by convention" into "confined by GRANT/REVOKE the database
// itself enforces." See the 2026-08-02 security audit, findings H-1/H-2.
func provisionSchema(ctx context.Context, d Deps, moduleName, schemaName, roleName string) (string, error) {
	// Create schema.
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quoteIdent(schemaName))); err != nil {
		return "", fmt.Errorf("create schema %s: %w", schemaName, err)
	}

	// A password already on file (installed_modules.db_role_password_enc)
	// means this role has been through this function before and is either
	// already a LOGIN role, or - the upgrade case just below - still the
	// old NOLOGIN role from a Core version predating this feature, with a
	// password generated but not yet applied because the ALTER ROLE
	// failed partway through a previous boot. Either way: if we already
	// have a password, reuse it rather than generating a new one. Any
	// running Deno worker for this module already holds a connection
	// string built from it (see deno.go's WorkerOptions.DBRolePassword);
	// rotating it here on every boot would silently break that worker's
	// next reconnect for no benefit.
	password, hasPassword, err := d.DB.GetModuleDBRolePassword(ctx, moduleName)
	if err != nil {
		return "", fmt.Errorf("read existing db role password for %s: %w", moduleName, err)
	}

	var roleExists bool
	if err := d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, roleName).Scan(&roleExists); err != nil {
		return "", fmt.Errorf("check role %s exists: %w", roleName, err)
	}

	if !hasPassword {
		password, err = generateRolePassword()
		if err != nil {
			return "", fmt.Errorf("generate db role password for %s: %w", moduleName, err)
		}
		// Persist the password BEFORE granting LOGIN with it. If Core
		// crashed or lost the DB connection between these two steps in the
		// other order, the role would come up LOGIN-capable with a
		// password nobody has a record of - permanently locking every
		// future caller (including this same function, next boot) out of
		// ever connecting as that role again short of a manual ALTER ROLE.
		// Writing the record first means the worst case of a crash here is
		// re-running this exact block with the same password already on
		// file (hasPassword would be true next time), which is a no-op.
		if err := d.DB.SetModuleDBRolePassword(ctx, moduleName, password); err != nil {
			return "", fmt.Errorf("persist db role password for %s: %w", moduleName, err)
		}
		// generateRolePassword returns a lowercase-hex string - no quote,
		// backslash, or other character SQL string-literal syntax needs
		// escaped, so embedding it directly between single quotes here is
		// safe without a general-purpose SQL string-literal quoting
		// helper. (Unlike roleName/schemaName, this value never came from
		// outside Core, so there's also no untrusted-input concern.)
		if roleExists {
			// Upgrade path: this role already existed as NOLOGIN, created
			// by a Core version before this feature. Flip it to LOGIN
			// with the new password instead of trying to (re-)CREATE it.
			if _, err := d.DB.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s LOGIN PASSWORD '%s'`, quoteIdent(roleName), password)); err != nil {
				return "", fmt.Errorf("alter role %s to login: %w", roleName, err)
			}
		} else {
			if _, err := d.DB.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, quoteIdent(roleName), password)); err != nil {
				return "", fmt.Errorf("create role %s: %w", roleName, err)
			}
		}
	} else if !roleExists {
		// Password on file but the role itself is missing. Shouldn't
		// normally happen - DROP ROLE only ever runs alongside clearing
		// the stored password together, in dropModuleSchema - but recover
		// cleanly rather than silently failing every migration/worker
		// start for this module: recreate the role with the password
		// already on file rather than generating (and having to persist)
		// a new one.
		if _, err := d.DB.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, quoteIdent(roleName), password)); err != nil {
			return "", fmt.Errorf("recreate role %s: %w", roleName, err)
		}
	}

	// Grants below are re-applied on every call, not just when the role is
	// first created - all idempotent, and cheap enough that tracking a
	// separate "have we already granted this" flag isn't worth the extra
	// state. GRANT ... ON ALL TABLES/SEQUENCES (as opposed to relying on
	// ALTER DEFAULT PRIVILEGES alone) matters for a module that already
	// has tables from before this function's default-privileges statement
	// existed - ALTER DEFAULT PRIVILEGES only ever affects objects created
	// after it runs, never retroactively.
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("GRANT USAGE, CREATE ON SCHEMA %s TO %s", quoteIdent(schemaName), quoteIdent(roleName))); err != nil {
		return "", fmt.Errorf("grant usage/create on %s to %s: %w", schemaName, roleName, err)
	}
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA %s GRANT ALL ON TABLES TO %s", quoteIdent(schemaName), quoteIdent(roleName))); err != nil {
		return "", fmt.Errorf("alter default privileges (tables) on %s for %s: %w", schemaName, roleName, err)
	}
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA %s GRANT ALL ON SEQUENCES TO %s", quoteIdent(schemaName), quoteIdent(roleName))); err != nil {
		return "", fmt.Errorf("alter default privileges (sequences) on %s for %s: %w", schemaName, roleName, err)
	}
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("GRANT ALL ON ALL TABLES IN SCHEMA %s TO %s", quoteIdent(schemaName), quoteIdent(roleName))); err != nil {
		return "", fmt.Errorf("grant all tables in %s to %s: %w", schemaName, roleName, err)
	}
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("GRANT ALL ON ALL SEQUENCES IN SCHEMA %s TO %s", quoteIdent(schemaName), quoteIdent(roleName))); err != nil {
		return "", fmt.Errorf("grant all sequences in %s to %s: %w", schemaName, roleName, err)
	}
	// The actual access boundary: without this, the role would inherit
	// PUBLIC's default USAGE grant on the public schema (every role does,
	// by default, in Postgres) and could resolve/reference anything else
	// living there, including Core's own tables. Built-in functions like
	// gen_random_uuid() that migrations rely on live in pg_catalog, which
	// every role can always see regardless of this REVOKE - so module
	// migrations that use them are unaffected.
	if _, err := d.DB.Exec(ctx, fmt.Sprintf("REVOKE ALL ON SCHEMA public FROM %s", quoteIdent(roleName))); err != nil {
		return "", fmt.Errorf("revoke public schema access from %s: %w", roleName, err)
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
		return "", fmt.Errorf("create module_migrations table: %w", err)
	}
	return password, nil
}

// modulePIIMigrated looks up whether moduleName's PII data has already been
// re-encrypted under its own derived key (db.Pool.IsModulePIIMigrated),
// for use as WorkerOptions.PIIMigrated before every Workers.Start call -
// same reasoning and pairing as moduleDBRolePassword below. Fails safe: any
// lookup error returns false ("not migrated"), which makes buildWorker
// grant the worker the legacy shared key alongside its derived one rather
// than risk cutting off a module's access to its own not-yet-migrated data
// because of a transient DB error.
func modulePIIMigrated(ctx context.Context, d Deps, moduleName string) bool {
	migrated, err := d.DB.IsModulePIIMigrated(ctx, moduleName)
	if err != nil {
		log.Printf("modules: could not check pii migration status for %q, assuming not migrated: %v", moduleName, err)
		return false
	}
	return migrated
}

// moduleDBRolePassword looks up the stored password for a module's Postgres
// LOGIN role (see db.Pool.GetModuleDBRolePassword) for use as
// WorkerOptions.DBRolePassword before every Workers.Start call - every call
// site in this package does the same lookup, so it's centralized here
// rather than repeated. Returns "" (never an error) on any failure,
// including "no password on file yet" - buildWorker's own empty-password
// check turns that into a clear, single error message at the one place
// that actually needs to fail the operation, instead of every call site
// having to decide separately how to react to a lookup failure here.
func moduleDBRolePassword(ctx context.Context, d Deps, moduleName string) string {
	password, ok, err := d.DB.GetModuleDBRolePassword(ctx, moduleName)
	if err != nil {
		log.Printf("modules: could not read db role password for %q: %v", moduleName, err)
		return ""
	}
	if !ok {
		log.Printf("modules: no db role password on file for %q yet - provisionSchema has not run for it", moduleName)
		return ""
	}
	return password
}

// generateRolePassword returns a fresh 256-bit random password, hex-encoded
// (so it is safe to embed directly in a SQL string literal - see
// provisionSchema's use of it - and in a postgres:// connection string
// without URL-escaping beyond what url.QueryEscape already handles for any
// string).
func generateRolePassword() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// connectAsModuleRole opens a single Postgres connection authenticated as
// roleName/password - not Core's own superuser connection (d.DB) - for
// running one module's migrations under its own, minimally-privileged
// role. Closed by the caller once the migration transaction is done; not
// pooled, since migrations run only during Install/Update, not on any
// request path.
func connectAsModuleRole(ctx context.Context, d Deps, roleName, password string) (*pgx.Conn, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s",
		url.QueryEscape(roleName), url.QueryEscape(password), d.DBHostPort, d.DBName)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect as %s: %w", roleName, err)
	}
	return conn, nil
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
