package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/passport-local/atlas/pkg/wire"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Server struct {
	DB     *pgxpool.Pool
	Tokens map[string]string
	Key    ed25519.PrivateKey
	KeyID  string
}
type apiError struct {
	Code   string
	Status int
}

func (e apiError) Error() string { return e.Code }
func reject(code string) error   { return apiError{code, 400} }
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func read(w http.ResponseWriter, r *http.Request, v any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if err != nil {
		return reject("invalid_request")
	}
	if wire.Decode(raw, v) != nil {
		return reject("invalid_request")
	}
	return nil
}
func tokenOK(got, want string) bool {
	return len(want) >= 32 && subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+want)) == 1
}
func (s *Server) authed(r *http.Request, org string) bool {
	return tokenOK(r.Header.Get("Authorization"), s.Tokens[org])
}
func (s *Server) wrap(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			var e apiError
			if errors.As(err, &e) {
				respond(w, e.Status, map[string]string{"code": e.Code})
				return
			}
			if errors.Is(err, pgx.ErrNoRows) {
				respond(w, 404, map[string]string{"code": "not_found"})
				return
			}
			respond(w, 409, map[string]string{"code": "conflict"})
		}
	}
}

func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(872103); CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	files, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, f := range files {
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", f.Name()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, _ := migrations.ReadFile("migrations/" + f.Name())
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", f.Name()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.DB.Ping(r.Context()) != nil {
			respond(w, 503, map[string]string{"status": "unavailable"})
			return
		}
		respond(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v0/organizations", s.wrap(s.organization))
	for path, kind := range map[string]string{"/v0/agents": "agent", "/v0/agents/{id}/keys": "runtime_key", "/v0/delegations": "delegation", "/v0/policy-keys": "policy_key", "/v0/policies": "policy", "/v0/revocations": "revocation", "/v0/organizations/{id}/rotations": "root_rotation", "/v0/receipts": "receipt"} {
		mux.HandleFunc("POST "+path, s.wrap(func(w http.ResponseWriter, r *http.Request) error { return s.mutation(w, r, kind) }))
	}
	mux.HandleFunc("GET /v0/organizations/{id}/trust", s.wrap(s.trust))
	mux.HandleFunc("GET /v0/overview", s.wrap(s.overview))
	mux.HandleFunc("GET /v0/receipts", s.wrap(s.receipts))
	mux.HandleFunc("GET /v0/events", s.wrap(s.events))
}
func (s *Server) organization(w http.ResponseWriter, r *http.Request) error {
	if !s.authed(r, "bootstrap") {
		return apiError{"unauthorized", 401}
	}
	var doc wire.Document
	if err := read(w, r, &doc); err != nil {
		return err
	}
	p, err := wire.Payload[wire.Organization](doc)
	if err != nil || !wire.ID(p.ID) || !wire.ID(p.RootKeyID) || p.Name == "" || p.CreatedAt <= 0 || doc.KeyID != p.RootKeyID {
		return reject("invalid_request")
	}
	if wire.Verify(doc, "organization", p.PublicKey) != nil {
		return reject("invalid_signature")
	}
	ctx := r.Context()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO organizations(id) VALUES($1)", p.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO root_keys(org_id,id,public_key) VALUES($1,$2,$3)", p.ID, p.RootKeyID, p.PublicKey); err != nil {
		return err
	}
	if err = insert(ctx, tx, p.ID, p.ID, doc); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	respond(w, 201, map[string]string{"id": p.ID})
	return nil
}
func insert(ctx context.Context, tx pgx.Tx, org, id string, doc wire.Document) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO records(org_id,kind,id,document) VALUES($1,$2,$3,$4)", org, doc.Kind, id, raw); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO outbox(org_id,topic,object_id,evidence_digest) VALUES($1,$2,$3,$4)", org, doc.Kind+".created", id, wire.Digest(doc))
	return err
}
func parent(ctx context.Context, tx pgx.Tx, org, kind, id string) error {
	var revoked bool
	if err := tx.QueryRow(ctx, "SELECT revoked FROM records WHERE org_id=$1 AND kind=$2 AND id=$3", org, kind, id).Scan(&revoked); err != nil {
		return reject("invalid_parent")
	}
	if revoked {
		return reject("revoked")
	}
	return nil
}
func (s *Server) mutation(w http.ResponseWriter, r *http.Request, kind string) error {
	var doc wire.Document
	if err := read(w, r, &doc); err != nil {
		return err
	}
	if doc.Kind != kind {
		return reject("invalid_request")
	}
	var base struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	if json.Unmarshal(doc.Payload, &base) != nil || !wire.ID(base.ID) || !wire.ID(base.OrgID) {
		return reject("invalid_request")
	}
	if !s.authed(r, base.OrgID) {
		return apiError{"unauthorized", 401}
	}
	ctx := r.Context()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active string
	if err = tx.QueryRow(ctx, "SELECT active_policy FROM organizations WHERE id=$1 FOR UPDATE", base.OrgID).Scan(&active); err != nil {
		return err
	}
	if err = parent(ctx, tx, base.OrgID, "organization", base.OrgID); err != nil {
		return err
	}
	var public string
	var revoked bool
	if kind == "receipt" {
		var raw []byte
		if err = tx.QueryRow(ctx, "SELECT document,revoked FROM records WHERE org_id=$1 AND kind='policy_key' AND id=$2", base.OrgID, doc.KeyID).Scan(&raw, &revoked); err != nil {
			return err
		}
		var cert wire.Document
		if wire.Decode(raw, &cert) != nil {
			return reject("invalid_request")
		}
		pk, e := wire.Payload[wire.PolicyKey](cert)
		if e != nil || !wire.Window(time.Now().Unix(), pk.NotBefore, pk.ExpiresAt) {
			return reject("expired")
		}
		public = pk.PublicKey
		var parentRevoked bool
		if err = tx.QueryRow(ctx, "SELECT revoked FROM root_keys WHERE org_id=$1 AND id=$2", base.OrgID, cert.KeyID).Scan(&parentRevoked); err != nil {
			return err
		}
		if parentRevoked {
			return reject("revoked")
		}
	} else {
		if err = tx.QueryRow(ctx, "SELECT public_key,revoked FROM root_keys WHERE org_id=$1 AND id=$2", base.OrgID, doc.KeyID).Scan(&public, &revoked); err != nil {
			return err
		}
	}
	if revoked {
		return reject("revoked")
	}
	if wire.Verify(doc, kind, public) != nil {
		return reject("invalid_signature")
	}
	validWindow := func(a, b int64) bool { return a > 0 && b > a && b-a <= 366*86400 }
	scopeOK := func(s wire.Scope) bool {
		if len(s.Actions) == 0 || len(s.Resources) == 0 || len(s.Audiences) == 0 {
			return false
		}
		for _, list := range [][]string{s.Actions, s.Resources, s.Audiences} {
			if len(list) > 32 {
				return false
			}
			for _, v := range list {
				if !wire.ID(v) {
					return false
				}
			}
		}
		return true
	}
	switch kind {
	case "agent":
		p, e := wire.Payload[wire.Agent](doc)
		if e != nil || p.Name == "" || len(p.Name) > 128 || p.CreatedAt <= 0 {
			return reject("invalid_request")
		}
	case "runtime_key":
		p, e := wire.Payload[wire.RuntimeKey](doc)
		if e != nil || !wire.ID(p.DelegationID) || p.AgentID != r.PathValue("id") || !validWindow(p.NotBefore, p.ExpiresAt) {
			return reject("invalid_request")
		}
		if _, e = wire.PublicKey(p.PublicKey); e != nil {
			return reject("invalid_request")
		}
		if err = parent(ctx, tx, p.OrgID, "agent", p.AgentID); err != nil {
			return err
		}
	case "delegation":
		p, e := wire.Payload[wire.Delegation](doc)
		if e != nil || !scopeOK(p.Scope) || !validWindow(p.NotBefore, p.ExpiresAt) {
			return reject("invalid_request")
		}
		if err = parent(ctx, tx, p.OrgID, "agent", p.AgentID); err != nil {
			return err
		}
		if err = parent(ctx, tx, p.OrgID, "runtime_key", p.RuntimeKeyID); err != nil {
			return err
		}
		var raw []byte
		if err = tx.QueryRow(ctx, "SELECT document FROM records WHERE org_id=$1 AND kind='runtime_key' AND id=$2", p.OrgID, p.RuntimeKeyID).Scan(&raw); err != nil {
			return err
		}
		var keyDoc wire.Document
		if wire.Decode(raw, &keyDoc) != nil {
			return reject("invalid_parent")
		}
		key, e := wire.Payload[wire.RuntimeKey](keyDoc)
		if e != nil || key.AgentID != p.AgentID || key.DelegationID != p.ID || p.NotBefore < key.NotBefore || p.ExpiresAt > key.ExpiresAt {
			return reject("invalid_parent")
		}
	case "policy_key":
		p, e := wire.Payload[wire.PolicyKey](doc)
		if e != nil || !scopeOK(p.Scope) || p.MaxTTL < 1 || p.MaxTTL > 60 || !validWindow(p.NotBefore, p.ExpiresAt) {
			return reject("invalid_request")
		}
		if _, e = wire.PublicKey(p.PublicKey); e != nil {
			return reject("invalid_request")
		}
	case "policy":
		p, e := wire.Payload[wire.Policy](doc)
		if e != nil || p.Version < 1 || p.Predecessor != active || !validWindow(p.NotBefore, p.ExpiresAt) || p.Predicate != wire.ProofProgram || len(p.Commitment) != 64 || p.Currency != "USD" || p.Asset != "iso4217:USD" || p.Network != "simulation" {
			return reject("policy_mismatch")
		}
		if _, e = hex.DecodeString(p.Commitment); e != nil {
			return reject("policy_mismatch")
		}
		if active == "" {
			if p.Version != 1 {
				return reject("policy_mismatch")
			}
		} else {
			var raw []byte
			if err = tx.QueryRow(ctx, "SELECT document FROM records WHERE org_id=$1 AND kind='policy' AND id=$2", base.OrgID, active).Scan(&raw); err != nil {
				return err
			}
			var prev wire.Document
			_ = json.Unmarshal(raw, &prev)
			pp, e := wire.Payload[wire.Policy](prev)
			if e != nil || p.Version != pp.Version+1 {
				return reject("policy_mismatch")
			}
		}
		if _, err = tx.Exec(ctx, "UPDATE organizations SET active_policy=$2 WHERE id=$1", base.OrgID, p.ID); err != nil {
			return err
		}
	case "revocation":
		p, e := wire.Payload[wire.Revocation](doc)
		if e != nil || !wire.ID(p.TargetID) || p.IssuedAt <= 0 || p.IssuedAt > time.Now().Unix() {
			return reject("invalid_request")
		}
		if p.TargetKind == "root_key" {
			tag, e := tx.Exec(ctx, "UPDATE root_keys SET revoked=true WHERE org_id=$1 AND id=$2", p.OrgID, p.TargetID)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return reject("not_found")
			}
		} else {
			switch p.TargetKind {
			case "agent", "runtime_key", "delegation", "policy_key", "policy", "organization":
			default:
				return reject("invalid_request")
			}
			tag, e := tx.Exec(ctx, "UPDATE records SET revoked=true WHERE org_id=$1 AND kind=$2 AND id=$3", p.OrgID, p.TargetKind, p.TargetID)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return reject("not_found")
			}
		}
	case "root_rotation":
		p, e := wire.Payload[wire.Rotation](doc)
		if e != nil || p.OrgID != r.PathValue("id") || p.PreviousKeyID != doc.KeyID || p.IssuedAt <= 0 || p.IssuedAt > time.Now().Unix() {
			return reject("invalid_request")
		}
		if _, e = wire.PublicKey(p.PublicKey); e != nil {
			return reject("invalid_request")
		}
		if _, err = tx.Exec(ctx, "INSERT INTO root_keys(org_id,id,public_key) VALUES($1,$2,$3)", p.OrgID, p.ID, p.PublicKey); err != nil {
			return err
		}
	case "receipt":
		p, e := wire.Payload[wire.Receipt](doc)
		if e != nil || p.ReceiptType != "authorization" || p.Decision != "allow" || !wire.ID(p.CapabilityID) || len(p.RequestDigest) != 64 || len(p.EvidenceDigest) != 64 || p.IssuedAt <= 0 {
			return reject("invalid_request")
		}
		raw, _ := json.Marshal(doc)
		if _, err = tx.Exec(ctx, "INSERT INTO receipts(id,org_id,document) VALUES($1,$2,$3)", p.ID, p.OrgID, raw); err != nil {
			return err
		}
	default:
		return reject("invalid_request")
	}
	if err = insert(ctx, tx, base.OrgID, base.ID, doc); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	respond(w, 201, map[string]string{"id": base.ID})
	return nil
}
func (s *Server) trust(w http.ResponseWriter, r *http.Request) error {
	org := r.PathValue("id")
	challenge := r.URL.Query().Get("challenge")
	if !wire.ID(org) || len(challenge) != 64 || !wire.ID(challenge) {
		return reject("invalid_request")
	}
	ctx := r.Context()
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	b := wire.Bundle{OrgID: org, Challenge: challenge, IssuedAt: time.Now().Unix(), Roots: []wire.Root{}, Records: []wire.Record{}}
	b.ExpiresAt = b.IssuedAt + 5
	if err = tx.QueryRow(ctx, "SELECT active_policy FROM organizations WHERE id=$1", org).Scan(&b.ActivePolicy); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT id,public_key,revoked FROM root_keys WHERE org_id=$1 ORDER BY id", org)
	if err != nil {
		return err
	}
	for rows.Next() {
		var root wire.Root
		if err = rows.Scan(&root.KeyID, &root.PublicKey, &root.Revoked); err != nil {
			rows.Close()
			return err
		}
		b.Roots = append(b.Roots, root)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	rows, err = tx.Query(ctx, "SELECT document,revoked FROM records WHERE org_id=$1 AND kind <> 'receipt' ORDER BY kind,id", org)
	if err != nil {
		return err
	}
	for rows.Next() {
		var raw []byte
		var v wire.Record
		if err = rows.Scan(&raw, &v.Revoked); err != nil {
			rows.Close()
			return err
		}
		if wire.Decode(raw, &v.Document) != nil {
			rows.Close()
			return reject("invalid_request")
		}
		b.Records = append(b.Records, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	doc, err := wire.Sign("trust_bundle", s.KeyID, b, s.Key)
	if err != nil {
		return err
	}
	respond(w, 200, doc)
	return nil
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) error {
	rows, err := s.DB.Query(r.Context(), "SELECT id,active_policy FROM organizations ORDER BY id")
	if err != nil {
		return err
	}
	orgs := []map[string]string{}
	for rows.Next() {
		var id, policy string
		if err = rows.Scan(&id, &policy); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, map[string]string{"id": id, "active_policy": policy})
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	rows, err = s.DB.Query(r.Context(), "SELECT org_id,kind,id,revoked,document FROM records WHERE kind IN ('agent','runtime_key','delegation','policy','policy_key') ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return err
	}
	defer rows.Close()
	records := []any{}
	for rows.Next() {
		var org, kind, id string
		var revoked bool
		var doc json.RawMessage
		if err = rows.Scan(&org, &kind, &id, &revoked, &doc); err != nil {
			return err
		}
		records = append(records, map[string]any{"org_id": org, "kind": kind, "id": id, "revoked": revoked, "document": doc})
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	respond(w, 200, map[string]any{"organizations": orgs, "records": records, "profile": wire.Profile, "freshness_seconds": 5})
	return nil
}
func (s *Server) receipts(w http.ResponseWriter, r *http.Request) error {
	rows, err := s.DB.Query(r.Context(), "SELECT document FROM receipts ORDER BY created_at DESC LIMIT 30")
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		out = append(out, raw)
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	respond(w, 200, out)
	return nil
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) error {
	org := r.URL.Query().Get("org_id")
	if !s.authed(r, org) {
		return apiError{"unauthorized", 401}
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	rows, err := s.DB.Query(r.Context(), "SELECT id,topic,object_id,evidence_digest FROM outbox WHERE org_id=$1 AND id>$2 ORDER BY id LIMIT 100", org, after)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id int64
		var topic, object, digest string
		if err = rows.Scan(&id, &topic, &object, &digest); err != nil {
			return err
		}
		out = append(out, map[string]any{"id": id, "topic": topic, "object_id": object, "evidence_digest": digest})
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	respond(w, 200, out)
	return nil
}

// SecurityHeaders apply to the local dashboard and HTTP API alike.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "invalid path", 400)
			return
		}
		next.ServeHTTP(w, r)
	})
}
