module github.com/modulab-project/modulab-core/backend

go 1.25.0

require (
	github.com/coreos/go-oidc/v3 v3.19.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/redis/go-redis/v9 v9.6.1
	golang.org/x/oauth2 v0.36.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/crypto v0.49.0 // indirect — TODO(2026-07-02): bump requires `go mod tidy` to regenerate go.sum, could not run it in this environment (no Go toolchain / no proxy.golang.org access). Run `go mod tidy && go build ./...` before committing.
	golang.org/x/sync v0.21.0 // indirect — TODO(2026-07-02): see x/crypto note above, same go.sum regeneration needed.
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
