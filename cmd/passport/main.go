package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/passport-local/atlas/internal/registry"
	"github.com/passport-local/atlas/pkg/verifier"
)

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = json.Unmarshal(b, v); err != nil {
		log.Fatal(err)
	}
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	mux := http.NewServeMux()
	if env("MODE", "registry") == "verifier" {
		var pins verifier.Pins
		readJSON(env("TRUST_FILE", "/public/trust.json"), &pins)
		config := verifier.Config{Pins: pins, RegistryURL: env("REGISTRY_URL", "http://registry:8080"), ProofURL: env("PROOF_URL", "http://globex-proof:8090"), Audience: env("AUDIENCE", "globex"), EnableZK: env("ENABLE_ZK", "1") == "1"}
		mux.HandleFunc("POST /v0/verify", config.Handler)
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
		})
	} else {
		db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		if err = registry.Migrate(ctx, db); err != nil {
			log.Fatal(err)
		}
		keyData, err := os.ReadFile(env("SIGNING_KEY_FILE", "/registry/registry.pem"))
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(keyData)
		if block == nil {
			log.Fatal("invalid signing key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			log.Fatal("Ed25519 required")
		}
		tokens := map[string]string{}
		readJSON(env("ADMIN_TOKENS_FILE", "/registry/admin.json"), &tokens)
		server := registry.Server{DB: db, Key: key, KeyID: "passport-registry-1", Tokens: tokens}
		server.Routes(mux)
		target, _ := url.Parse(env("GLOBEX_URL", "http://globex:8081"))
		proxy := httputil.NewSingleHostReverseProxy(target)
		mux.HandleFunc("GET /v0/globex-receipts", func(w http.ResponseWriter, r *http.Request) { r.URL.Path = "/v0/receipts"; proxy.ServeHTTP(w, r) })
		mux.Handle("GET /api/", http.StripPrefix("/api/", http.FileServer(http.Dir("api"))))
		mux.Handle("GET /", http.FileServer(http.Dir("web")))
	}
	server := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: registry.SecurityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	log.Printf("passport %s listening on %s", env("MODE", "registry"), server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
