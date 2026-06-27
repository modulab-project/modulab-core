package auth

import "context"

// sessionContextKey is the unexported key used to store a validated Session
// in a request context. Unexported prevents collisions with other packages.
type sessionContextKey struct{}

// ContextWithSession returns a child of ctx carrying sess, so downstream
// handlers can call SessionFromContext without re-validating the token.
// Called by RequireSuperAdminMiddleware so any handler it wraps can retrieve
// the validated session (e.g. for audit logging) without needing to import
// the auth package or re-parse the bearer token.
func ContextWithSession(ctx context.Context, sess Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, sess)
}

// SessionFromContext retrieves the Session stored by ContextWithSession.
// ok is false when no session has been stored - any handler that has not
// been wrapped by RequireSuperAdminMiddleware or an equivalent that calls
// ContextWithSession will see ok = false.
func SessionFromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(sessionContextKey{}).(Session)
	return sess, ok
}
