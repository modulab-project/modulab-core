// Command core is the entry point for the modulab-core backend.
//
// This is the v1 skeleton: it boots an HTTP server with a /healthz endpoint
// and reports whether Postgres and Valkey are reachable at the TCP level.
// It deliberately does not yet speak the Postgres or Valkey wire protocols,
// run migrations, or supervise the Deno subprocess (spec section 4.7) - those
// land in follow-up commits once a real driver/dependency set is vendored.
// The goal of this commit is a buildable, runnable foundation that the rest
// of Core grows from.
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/config"
)

type healthStatus struct {
	Status         string `json:"status"`
	PostgresUp     bool   `json:"postgres_reachable"`
	ValkeyUp       bool   `json:"valkey_reachable"`
	MasterKeySetUp bool   `json:"master_key_present"`
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		status := healthStatus{
			Status:         "ok",
			PostgresUp:     tcpReachable(cfg.DBHost, cfg.DBPort),
			ValkeyUp:       tcpReachable(cfg.ValkeyHost, cfg.ValkeyPort),
			MasterKeySetUp: cfg.MasterKey != "",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})

	log.Printf("modulab-core listening on %s (group prefix %q)", cfg.HTTPAddr, cfg.GroupPrefix)
	if err := http.ListenAndServe(cfg.HTTPAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// tcpReachable performs a best-effort TCP dial to confirm a dependency is at
// least listening on its port. It is not a substitute for a real protocol
// handshake and will be replaced once the Postgres/Valkey clients land.
func tcpReachable(host, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
