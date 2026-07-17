// Tier 1 (config-driven CRUD) support - see docs/tier1-crud-plan.md for the
// full design. A Tier 1 module declares a table and its fields in
// manifest.yaml's crud block and ships no handler code at all; Core serves a
// generic REST API directly against the module's own module_{name} schema
// instead of proxying to a Deno worker (see ServeCrudRequest's call site in
// router.go's ModuleProxyHandler).
//
// The table itself is NOT auto-generated from crud.fields - the module
// author still ships migrations/001_initial.sql, same as Tier 2/3, so Core
// never has to translate manifest field types into DDL. validateCrudTable
// instead cross-checks the author's migration against the manifest at
// install/update time, so a mismatch is a clear install-time error instead
// of an opaque SQL failure on the first API call.
package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// crudIdentRe restricts crud.table and every crud.fields[].name to safe,
// unquoted Postgres identifiers - lowercase, must start with a letter. Column
// names are only ever interpolated into SQL after quoteIdent (defense in
// depth, matching moduleIdentifiers/quoteIdent's convention in migrations.go),
// but rejecting anything outside this shape up front at manifest-validation
// time means a malformed name never even reaches SQL-building code.
var crudIdentRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// crudUUIDRe validates a client-supplied uuid-typed field value (RFC 4122
// text form). Row IDs in path segments are not checked against this - they
// go straight into a $-placeholder, so a malformed one just fails the query
// (surfaced as 404/500, not a SQL-injection risk).
var crudUUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// implicitCrudColumnNames are managed by Core, never by the author's own
// crud.fields - see the CREATE TABLE snippet in docs/tier1-crud-plan.md.
// createdByColumn is only actually present when crud.owner_scoped is true.
const (
	idColumn        = "id"
	createdAtColumn = "created_at"
	updatedAtColumn = "updated_at"
	createdByColumn = "created_by"
)

// crudFieldTypeInfo maps a manifest crud.fields[].type to the Postgres
// information_schema.columns.data_type value(s) validateCrudTable accepts
// for it, and how the generic handler parses/encodes JSON values of that
// type. Kept as a single table so "what types exist" has one source of
// truth across validation, install-time checking, and request handling.
var crudFieldTypeInfo = map[string][]string{
	"string":   {"text", "character varying"},
	"text":     {"text"},
	"integer":  {"integer", "bigint", "smallint"},
	"float":    {"real", "double precision", "numeric"},
	"boolean":  {"boolean"},
	"date":     {"date"},
	"datetime": {"timestamp without time zone", "timestamp with time zone"},
	"uuid":     {"uuid"},
}

// validateCrudFields checks crud's structural validity - identifier shape,
// duplicate names, and collisions with the implicit columns Core itself
// manages. Called from validateManifestTier at install/update time, before
// any database access (validateCrudTable, below, checks the rest - that the
// author's actual migration matches this declaration).
func validateCrudFields(crud *ManifestCrud) error {
	if !crudIdentRe.MatchString(crud.Table) {
		return fmt.Errorf("crud.table %q must be lowercase, start with a letter, and contain only [a-z0-9_]", crud.Table)
	}
	seen := map[string]bool{
		idColumn:        true,
		createdAtColumn: true,
		updatedAtColumn: true,
		createdByColumn: true,
	}
	for _, f := range crud.Fields {
		if !crudIdentRe.MatchString(f.Name) {
			return fmt.Errorf("crud.fields: %q must be lowercase, start with a letter, and contain only [a-z0-9_]", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("crud.fields: %q is declared more than once, or collides with a Core-managed column (id/created_at/updated_at/created_by)", f.Name)
		}
		seen[f.Name] = true
		if _, ok := crudFieldTypeInfo[f.Type]; !ok {
			return fmt.Errorf("crud.fields: %q has unknown type %q", f.Name, f.Type)
		}
		// Encrypted values are stored as a base64 ciphertext string - only
		// string/text columns can hold that without losing the original
		// type on the way back out, so encryption is restricted to those.
		if f.Encrypted && f.Type != "string" && f.Type != "text" {
			return fmt.Errorf("crud.fields: %q: encrypted is only supported for type \"string\" or \"text\"", f.Name)
		}
	}
	return nil
}

// validateCrudTable cross-checks a Tier 1 module's actual, already-migrated
// table (in its own module_{name} schema) against its manifest's crud
// declaration. Called by Install/Update after runModuleMigrations, before
// the module is marked active - a mismatch is rejected here, with a clear
// error naming the column, instead of surfacing as a raw SQL error the first
// time someone calls the module's API.
func validateCrudTable(ctx context.Context, d Deps, moduleName string, crud *ManifestCrud) error {
	schemaName, _, err := moduleIdentifiers(moduleName)
	if err != nil {
		return err
	}

	rows, err := d.DB.Query(ctx, `
		SELECT column_name, data_type
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`, schemaName, crud.Table)
	if err != nil {
		return fmt.Errorf("modules: crud %q: read columns of %s.%s: %w", moduleName, schemaName, crud.Table, err)
	}
	defer rows.Close()

	actual := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			return fmt.Errorf("modules: crud %q: scan column: %w", moduleName, err)
		}
		actual[name] = dataType
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(actual) == 0 {
		return fmt.Errorf("modules: crud %q: table %s.%s does not exist - did migrations/001_initial.sql create it?", moduleName, schemaName, crud.Table)
	}

	checkColumn := func(name string, acceptable []string) error {
		dataType, ok := actual[name]
		if !ok {
			return fmt.Errorf("modules: crud %q: table %s.%s is missing column %q", moduleName, schemaName, crud.Table, name)
		}
		for _, want := range acceptable {
			if dataType == want {
				return nil
			}
		}
		return fmt.Errorf("modules: crud %q: table %s.%s column %q has type %q, expected one of %v", moduleName, schemaName, crud.Table, name, dataType, acceptable)
	}

	if err := checkColumn(idColumn, []string{"uuid"}); err != nil {
		return err
	}
	if err := checkColumn(createdAtColumn, []string{"timestamp with time zone", "timestamp without time zone"}); err != nil {
		return err
	}
	if err := checkColumn(updatedAtColumn, []string{"timestamp with time zone", "timestamp without time zone"}); err != nil {
		return err
	}
	if crud.OwnerScoped {
		if err := checkColumn(createdByColumn, []string{"text"}); err != nil {
			return err
		}
	}
	for _, f := range crud.Fields {
		if err := checkColumn(f.Name, crudFieldTypeInfo[f.Type]); err != nil {
			return err
		}
	}
	return nil
}

// ── Generic CRUD HTTP handler (request-serving side) ────────────────────────

const (
	defaultCrudPageSize = 50
	maxCrudPageSize     = 200
)

// ServeCrudRequest handles one HTTP request for a Tier 1 module - called from
// ModuleProxyHandler (router.go) instead of dispatching to a Deno worker,
// once it sees the installed module's tier is 1. manifestJSON is the raw
// manifest column already fetched by the caller (db.InstalledModuleRow.Manifest).
func ServeCrudRequest(w http.ResponseWriter, r *http.Request, d Deps, moduleName string, manifestJSON json.RawMessage, sess auth.Session) {
	var mf Manifest
	if err := json.Unmarshal(manifestJSON, &mf); err != nil || mf.Crud == nil {
		http.Error(w, "module: invalid stored manifest", http.StatusInternalServerError)
		return
	}
	crud := mf.Crud

	crudPath := strings.TrimPrefix(r.URL.Path, "/v1/modules/"+moduleName+"/api/")
	crudPath = strings.Trim(crudPath, "/")
	parts := strings.SplitN(crudPath, "/", 2)
	table := parts[0]
	var rowID string
	if len(parts) == 2 {
		rowID = parts[1]
	}

	if table != crud.Table {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	schemaName, _, err := moduleIdentifiers(moduleName)
	if err != nil {
		http.Error(w, "module: invalid name", http.StatusInternalServerError)
		return
	}

	switch {
	case r.Method == http.MethodGet && rowID == "":
		listCrudRows(w, r, d, schemaName, crud, sess)
	case r.Method == http.MethodPost && rowID == "":
		createCrudRow(w, r, d, schemaName, crud, sess)
	case r.Method == http.MethodPatch && rowID != "":
		updateCrudRow(w, r, d, schemaName, crud, sess, rowID)
	case r.Method == http.MethodDelete && rowID != "":
		deleteCrudRow(w, r, d, schemaName, crud, sess, rowID)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// crudSelectColumns returns the full column list (implicit + declared) in a
// stable order, used for both SELECT and building the JSON response.
func crudSelectColumns(crud *ManifestCrud) []string {
	cols := []string{idColumn, createdAtColumn, updatedAtColumn}
	if crud.OwnerScoped {
		cols = append(cols, createdByColumn)
	}
	for _, f := range crud.Fields {
		cols = append(cols, f.Name)
	}
	return cols
}

// crudColumnIsUUID reports whether column name is uuid-typed - the implicit
// id column always is, a declared field is if its manifest type is "uuid".
func crudColumnIsUUID(crud *ManifestCrud, name string) bool {
	if name == idColumn {
		return true
	}
	for _, f := range crud.Fields {
		if f.Name == name && f.Type == "uuid" {
			return true
		}
	}
	return false
}

// quotedCrudSelectColumn returns the column reference to use in a SELECT/
// RETURNING list. uuid-typed columns are cast to text and re-aliased back to
// their own name: pgx's default "any" scan target for uuid decodes to
// [16]byte, and encoding/json only base64-encodes []byte slices, not fixed-
// size [16]byte arrays - it marshals those as a plain JSON array of 16
// numbers instead of a UUID string, which then breaks on the way back in
// (e.g. the frontend template-stringifying that array into a URL path
// produces something like ".../notes/199,216,197,...", not a valid uuid).
func quotedCrudSelectColumn(crud *ManifestCrud, name string) string {
	if crudColumnIsUUID(crud, name) {
		return quoteIdent(name) + "::text AS " + quoteIdent(name)
	}
	return quoteIdent(name)
}

func listCrudRows(w http.ResponseWriter, r *http.Request, d Deps, schemaName string, crud *ManifestCrud, sess auth.Session) {
	pageSize := defaultCrudPageSize
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if pageSize > maxCrudPageSize {
		pageSize = maxCrudPageSize
	}
	page := 1
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	offset := (page - 1) * pageSize

	cols := crudSelectColumns(crud)
	quotedCols := make([]string, len(cols))
	for i, c := range cols {
		quotedCols[i] = quotedCrudSelectColumn(crud, c)
	}

	query := fmt.Sprintf("SELECT %s FROM %s.%s", strings.Join(quotedCols, ", "), quoteIdent(schemaName), quoteIdent(crud.Table))
	args := []any{}
	if crud.OwnerScoped {
		query += fmt.Sprintf(" WHERE %s = $1", quoteIdent(createdByColumn))
		args = append(args, sess.UserID)
	}
	query += fmt.Sprintf(" ORDER BY %s DESC LIMIT %d OFFSET %d", quoteIdent(createdAtColumn), pageSize, offset)

	rows, err := d.DB.Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	maps, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	out := make([]map[string]any, 0, len(maps))
	for _, m := range maps {
		if err := decryptCrudRow(crud, m, d.PIIKey); err != nil {
			http.Error(w, "decrypt failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, m)
	}
	writeModuleJSON(w, http.StatusOK, out)
}

func createCrudRow(w http.ResponseWriter, r *http.Request, d Deps, schemaName string, crud *ManifestCrud, sess auth.Session) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	insertCols := []string{}
	insertVals := []any{}
	for _, f := range crud.Fields {
		raw, present := body[f.Name]
		if !present || string(raw) == "null" {
			if f.Required {
				http.Error(w, fmt.Sprintf("field %q is required", f.Name), http.StatusBadRequest)
				return
			}
			continue
		}
		val, err := decodeCrudFieldValue(f, raw)
		if err != nil {
			http.Error(w, fmt.Sprintf("field %q: %v", f.Name, err), http.StatusBadRequest)
			return
		}
		if f.Encrypted {
			enc, err := encryptCrudValue(d.PIIKey, val)
			if err != nil {
				http.Error(w, "encryption failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			val = enc
		}
		insertCols = append(insertCols, f.Name)
		insertVals = append(insertVals, val)
	}

	if crud.OwnerScoped {
		insertCols = append(insertCols, createdByColumn)
		insertVals = append(insertVals, sess.UserID)
	}

	placeholders := make([]string, len(insertCols))
	quotedCols := make([]string, len(insertCols))
	for i, c := range insertCols {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		quotedCols[i] = quoteIdent(c)
	}

	returnCols := crudSelectColumns(crud)
	quotedReturnCols := make([]string, len(returnCols))
	for i, c := range returnCols {
		quotedReturnCols[i] = quotedCrudSelectColumn(crud, c)
	}

	query := fmt.Sprintf("INSERT INTO %s.%s (%s) VALUES (%s) RETURNING %s",
		quoteIdent(schemaName), quoteIdent(crud.Table),
		strings.Join(quotedCols, ", "), strings.Join(placeholders, ", "),
		strings.Join(quotedReturnCols, ", "))

	rows, err := d.DB.Query(r.Context(), query, insertVals...)
	if err != nil {
		http.Error(w, "insert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	m, err := pgx.CollectExactlyOneRow(rows, pgx.RowToMap)
	if err != nil {
		http.Error(w, "insert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := decryptCrudRow(crud, m, d.PIIKey); err != nil {
		http.Error(w, "decrypt failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeModuleJSON(w, http.StatusCreated, m)
}

func updateCrudRow(w http.ResponseWriter, r *http.Request, d Deps, schemaName string, crud *ManifestCrud, sess auth.Session, rowID string) {
	if !ownsCrudRow(w, r, d, schemaName, crud, sess, rowID) {
		return
	}

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	setCols := []string{}
	setVals := []any{}
	for _, f := range crud.Fields {
		raw, present := body[f.Name]
		if !present {
			continue
		}
		if string(raw) == "null" {
			if f.Required {
				http.Error(w, fmt.Sprintf("field %q is required and cannot be cleared", f.Name), http.StatusBadRequest)
				return
			}
			setCols = append(setCols, f.Name)
			setVals = append(setVals, nil)
			continue
		}
		val, err := decodeCrudFieldValue(f, raw)
		if err != nil {
			http.Error(w, fmt.Sprintf("field %q: %v", f.Name, err), http.StatusBadRequest)
			return
		}
		if f.Encrypted {
			enc, err := encryptCrudValue(d.PIIKey, val)
			if err != nil {
				http.Error(w, "encryption failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			val = enc
		}
		setCols = append(setCols, f.Name)
		setVals = append(setVals, val)
	}

	setClauses := make([]string, 0, len(setCols)+1)
	args := make([]any, 0, len(setCols)+1)
	for i, c := range setCols {
		args = append(args, setVals[i])
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", quoteIdent(c), i+1))
	}
	setClauses = append(setClauses, fmt.Sprintf("%s = now()", quoteIdent(updatedAtColumn)))
	args = append(args, rowID)

	query := fmt.Sprintf("UPDATE %s.%s SET %s WHERE %s = $%d",
		quoteIdent(schemaName), quoteIdent(crud.Table),
		strings.Join(setClauses, ", "), quoteIdent(idColumn), len(args))

	if _, err := d.DB.Exec(r.Context(), query, args...); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func deleteCrudRow(w http.ResponseWriter, r *http.Request, d Deps, schemaName string, crud *ManifestCrud, sess auth.Session, rowID string) {
	if !ownsCrudRow(w, r, d, schemaName, crud, sess, rowID) {
		return
	}
	query := fmt.Sprintf("DELETE FROM %s.%s WHERE %s = $1", quoteIdent(schemaName), quoteIdent(crud.Table), quoteIdent(idColumn))
	if _, err := d.DB.Exec(r.Context(), query, rowID); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ownsCrudRow checks that rowID exists and, when crud.OwnerScoped, that it
// belongs to sess - strictly, with no exception for any role (see
// docs/tier1-crud-plan.md). Writes the appropriate error response itself
// (404 if the row doesn't exist at all, 403 if it exists but belongs to
// someone else) and returns false on any failure, so callers can just
// `if !ownsCrudRow(...) { return }`. When crud.OwnerScoped is false, only
// existence is checked - every row is shared, so there is no owner to
// compare against.
func ownsCrudRow(w http.ResponseWriter, r *http.Request, d Deps, schemaName string, crud *ManifestCrud, sess auth.Session, rowID string) bool {
	if !crud.OwnerScoped {
		query := fmt.Sprintf("SELECT 1 FROM %s.%s WHERE %s = $1", quoteIdent(schemaName), quoteIdent(crud.Table), quoteIdent(idColumn))
		var exists int
		if err := d.DB.QueryRow(r.Context(), query, rowID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "not found", http.StatusNotFound)
			} else {
				http.Error(w, "lookup failed: "+err.Error(), http.StatusInternalServerError)
			}
			return false
		}
		return true
	}

	query := fmt.Sprintf("SELECT %s FROM %s.%s WHERE %s = $1", quoteIdent(createdByColumn), quoteIdent(schemaName), quoteIdent(crud.Table), quoteIdent(idColumn))
	var createdBy string
	if err := d.DB.QueryRow(r.Context(), query, rowID).Scan(&createdBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "lookup failed: "+err.Error(), http.StatusInternalServerError)
		}
		return false
	}
	if createdBy != sess.UserID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// decodeCrudFieldValue parses raw (one field's JSON value from the request
// body) according to f.Type, rejecting anything that doesn't match - the
// server-side half of type validation (the fallback UI is expected to do
// the same client-side, but a direct API call must not be able to bypass
// it). Returns a value pgx can bind directly to the target column.
func decodeCrudFieldValue(f ManifestCrudField, raw json.RawMessage) (any, error) {
	switch f.Type {
	case "string", "text":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("expected a string")
		}
		return s, nil
	case "integer":
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, errors.New("expected an integer")
		}
		i, err := n.Int64()
		if err != nil {
			return nil, fmt.Errorf("expected an integer, got %q", n.String())
		}
		return i, nil
	case "float":
		var f64 float64
		if err := json.Unmarshal(raw, &f64); err != nil {
			return nil, errors.New("expected a number")
		}
		return f64, nil
	case "boolean":
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, errors.New("expected a boolean")
		}
		return b, nil
	case "date":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("expected a date string (YYYY-MM-DD)")
		}
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return nil, fmt.Errorf("expected a date string (YYYY-MM-DD), got %q", s)
		}
		return t, nil
	case "datetime":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("expected an RFC3339 datetime string")
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, fmt.Errorf("expected an RFC3339 datetime string, got %q", s)
		}
		return t, nil
	case "uuid":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || !crudUUIDRe.MatchString(s) {
			return nil, errors.New("expected a UUID string")
		}
		return s, nil
	default:
		// Unreachable in practice - validateCrudFields already rejects
		// unknown types at install/update time - but fail closed rather
		// than silently accepting an unvalidated value if that guarantee
		// is ever broken.
		return nil, fmt.Errorf("unsupported field type %q", f.Type)
	}
}

// encryptCrudValue encrypts val (always a string - validateCrudFields
// restricts encrypted to string/text fields) with AES-256-GCM under piiKey,
// for storage in a text column. See crypto.Encrypt's doc comment for the
// nonce/ciphertext format.
func encryptCrudValue(piiKey string, val any) (string, error) {
	if piiKey == "" {
		return "", errors.New("encryption is not configured (MODULAB_MODULE_PII_KEY is unset)")
	}
	s, ok := val.(string)
	if !ok {
		return "", errors.New("only string/text fields can be encrypted")
	}
	return crypto.Encrypt(piiKey, s)
}

// decryptCrudRow decrypts every crud.fields[].encrypted column in m (a row
// already fetched via pgx.RowToMap) in place. Called on every row returned
// to a client - list, create, and (implicitly, via the client re-fetching)
// update. An empty stored value is left as-is rather than decrypted (never
// written that way by createCrudRow/updateCrudRow, but a defensive no-op
// here rather than a confusing decrypt error either way).
func decryptCrudRow(crud *ManifestCrud, m map[string]any, piiKey string) error {
	for _, f := range crud.Fields {
		if !f.Encrypted {
			continue
		}
		raw, ok := m[f.Name]
		if !ok || raw == nil {
			continue
		}
		ciphertext, ok := raw.(string)
		if !ok {
			return fmt.Errorf("field %q: encrypted column did not return a string", f.Name)
		}
		if ciphertext == "" {
			continue
		}
		if piiKey == "" {
			return errors.New("encryption is not configured (MODULAB_MODULE_PII_KEY is unset)")
		}
		plain, err := crypto.Decrypt(piiKey, ciphertext)
		if err != nil {
			return fmt.Errorf("field %q: %w", f.Name, err)
		}
		m[f.Name] = plain
	}
	return nil
}
