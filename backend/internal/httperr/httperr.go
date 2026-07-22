// Package httperr provides the one place every handler in this codebase
// should go through when an internal error (a DB error, a Valkey error, a
// master-key resolution failure, ...) needs to become an HTTP response.
//
// Before this package existed, the near-universal pattern across every
// handler package was http.Error(w, err.Error(), http.StatusInternalServerError)
// - convenient, but it means whatever the underlying error happens to say
// goes straight to the client. For a pgx/Postgres error that can include
// table/column/constraint names or fragments of the failing query; for a
// Valkey error, internal key names; in general, exactly the kind of
// implementation detail an API response should never carry, useful mostly
// to an attacker doing reconnaissance. Found during a security review pass
// (2026-07-22) that counted ~90 call sites doing this across 17 files.
//
// Internal is a drop-in replacement for that exact pattern: same two
// meaningful arguments (w, err), same effect from the caller's point of
// view (a 500 is written, nothing further must be written by the caller
// afterward) - only the response body changes, from err.Error() to a fixed
// generic string, with the real error logged server-side instead via
// runtime.Caller so every call site is still individually diagnosable from
// the log without having to hand-write a label at each of those ~90
// places.
package httperr

import (
	"log"
	"net/http"
	"path/filepath"
	"runtime"
)

// Internal logs err server-side (prefixed with the caller's file:line, so
// any of this package's many call sites remains distinguishable in the log
// without a hand-written label at each one) and writes a fixed, generic
// 500 response to w - never err.Error() itself. Callers use this exactly
// like the http.Error(w, err.Error(), http.StatusInternalServerError) it
// replaces: call it, then return without writing anything further.
func Internal(w http.ResponseWriter, err error) {
	if _, file, line, ok := runtime.Caller(1); ok {
		log.Printf("%s:%d: %v", filepath.Base(file), line, err)
	} else {
		// Should not happen on any real Go runtime - runtime.Caller only
		// fails to unwind the stack in exotic situations. Logged anyway so
		// the error itself is never silently dropped even in that case.
		log.Printf("internal error (unknown caller): %v", err)
	}
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
