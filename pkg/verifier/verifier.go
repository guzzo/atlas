// Package verifier verifies Passport evidence using public pins and live state.
// It never consumes a nonce or executes an action; the resource server must do
// both atomically in its own transaction after a successful result.
package verifier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/passport-local/atlas/pkg/wire"
)

type Pins struct {
	RegistryKeyID     string                       `json:"registry_key_id"`
	RegistryPublicKey string                       `json:"registry_public_key"`
	TrustedRoots      map[string]map[string]string `json:"trusted_roots"`
}
type Config struct {
	Pins        Pins
	RegistryURL string
	ProofURL    string
	Audience    string
	EnableZK    bool
	Client      *http.Client
	Now         func() time.Time
}
type Result struct {
	Decision       string   `json:"decision"`
	Code           string   `json:"code"`
	RequestDigest  string   `json:"request_digest"`
	EvidenceDigest string   `json:"evidence_digest"`
	PolicyVersion  string   `json:"policy_version"`
	StateIssuedAt  int64    `json:"state_issued_at"`
	ValidUntil     int64    `json:"valid_until"`
	Trace          []string `json:"trace"`
}
type Failure struct{ Code string }

func (e *Failure) Error() string { return e.Code }
func fail(code string) error     { return &Failure{code} }
func Code(err error) string {
	if e, ok := err.(*Failure); ok {
		return e.Code
	}
	return "unavailable"
}

func (c Config) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 3 * time.Second}
}
func (c Config) now() int64 {
	if c.Now != nil {
		return c.Now().Unix()
	}
	return time.Now().Unix()
}
func (c Config) bundle(ctx context.Context, org string) (wire.Bundle, error) {
	var b wire.Bundle
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return b, err
	}
	challenge := hex.EncodeToString(nonce)
	req, err := http.NewRequestWithContext(ctx, "GET", c.RegistryURL+"/v0/organizations/"+url.PathEscape(org)+"/trust?challenge="+challenge, nil)
	if err != nil {
		return b, err
	}
	res, err := c.client().Do(req)
	if err != nil {
		return b, fail("unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return b, fail("unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return b, err
	}
	var doc wire.Document
	if wire.Decode(raw, &doc) != nil || doc.KeyID != c.Pins.RegistryKeyID || wire.Verify(doc, "trust_bundle", c.Pins.RegistryPublicKey) != nil {
		return b, fail("invalid_signature")
	}
	b, err = wire.Payload[wire.Bundle](doc)
	if err != nil {
		return b, fail("invalid_request")
	}
	if b.OrgID != org || b.Challenge != challenge || b.ExpiresAt-b.IssuedAt > 5 || !wire.Window(c.now(), b.IssuedAt, b.ExpiresAt) {
		return b, fail("stale_state")
	}
	return b, nil
}

func (c Config) Verify(ctx context.Context, e wire.Evidence) (Result, error) {
	out := Result{Decision: "deny", Trace: []string{}, RequestDigest: wire.Digest(e.Request.Payload), EvidenceDigest: wire.Digest(e)}
	deny := func(code string) (Result, error) { out.Code = code; return out, fail(code) }
	r, err := wire.Payload[wire.Request](e.Request)
	if err != nil {
		return deny("invalid_request")
	}
	trusted, ok := c.Pins.TrustedRoots[r.IssuerOrg]
	if !ok {
		return deny("untrusted_issuer")
	}
	out.Trace = append(out.Trace, "issuer_pinned")
	b, err := c.bundle(ctx, r.IssuerOrg)
	if err != nil {
		return deny(Code(err))
	}
	out.StateIssuedAt = b.IssuedAt
	rootVerify := func(d wire.Document, kind string) error {
		public, ok := trusted[d.KeyID]
		if !ok {
			return fail("untrusted_issuer")
		}
		found := false
		for _, root := range b.Roots {
			if root.KeyID == d.KeyID {
				if root.Revoked {
					return fail("revoked")
				}
				if root.PublicKey != public {
					return fail("untrusted_issuer")
				}
				found = true
			}
		}
		if !found {
			return fail("untrusted_issuer")
		}
		if wire.Verify(d, kind, public) != nil {
			return fail("invalid_signature")
		}
		return nil
	}
	record := func(kind, id string) (wire.Document, error) {
		for _, v := range b.Records {
			var p struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(v.Document.Payload, &p) != nil {
				continue
			}
			if v.Document.Kind == kind && p.ID == id {
				if v.Revoked {
					return wire.Document{}, fail("revoked")
				}
				if err := rootVerify(v.Document, kind); err != nil {
					return wire.Document{}, err
				}
				return v.Document, nil
			}
		}
		return wire.Document{}, fail("denied")
	}
	orgDoc, err := record("organization", r.IssuerOrg)
	if err != nil {
		return deny(Code(err))
	}
	org, err := wire.Payload[wire.Organization](orgDoc)
	if err != nil || org.ID != r.IssuerOrg {
		return deny("invalid_request")
	}
	agentDoc, err := record("agent", r.AgentID)
	if err != nil {
		return deny(Code(err))
	}
	agent, err := wire.Payload[wire.Agent](agentDoc)
	if err != nil || agent.OrgID != r.IssuerOrg {
		return deny("denied")
	}
	keyDoc, err := record("runtime_key", r.RuntimeKeyID)
	if err != nil {
		return deny(Code(err))
	}
	key, err := wire.Payload[wire.RuntimeKey](keyDoc)
	if err != nil || key.OrgID != r.IssuerOrg || key.AgentID != r.AgentID || key.DelegationID != r.DelegationID {
		return deny("denied")
	}
	delDoc, err := record("delegation", r.DelegationID)
	if err != nil {
		return deny(Code(err))
	}
	if wire.Digest(delDoc) != wire.Digest(e.Delegation) {
		return deny("invalid_signature")
	}
	d, err := wire.Payload[wire.Delegation](delDoc)
	if err != nil || d.OrgID != r.IssuerOrg || d.AgentID != r.AgentID || d.RuntimeKeyID != r.RuntimeKeyID {
		return deny("denied")
	}
	out.Trace = append(out.Trace, "organization_and_delegation_signatures")
	if e.Request.KeyID != key.ID || wire.Verify(e.Request, "request", key.PublicKey) != nil {
		return deny("invalid_signature")
	}
	out.Trace = append(out.Trace, "runtime_proof_of_possession")
	if r.Audience != c.Audience || !wire.InScope(d.Scope, r.Action, r.Resource, r.Audience) {
		return deny("denied")
	}
	now := c.now()
	if !wire.Window(now, r.IssuedAt, r.ExpiresAt) || !wire.Window(now, key.NotBefore, key.ExpiresAt) || !wire.Window(now, d.NotBefore, d.ExpiresAt) {
		return deny("expired")
	}
	if wire.ValidRequest(r, now) != nil {
		return deny("invalid_request")
	}
	if r.IssuedAt < key.NotBefore || r.IssuedAt < d.NotBefore || r.ExpiresAt > key.ExpiresAt || r.ExpiresAt > d.ExpiresAt {
		return deny("denied")
	}
	out.Trace = append(out.Trace, "audience_scope_and_request_window", "fresh_key_delegation_and_policy_state")
	cap, err := wire.Payload[wire.Capability](e.Capability)
	if err != nil || !wire.ID(cap.CapabilityID) {
		return deny("invalid_request")
	}
	out.PolicyVersion = cap.PolicyVersion
	pkDoc, err := record("policy_key", e.Capability.KeyID)
	if err != nil {
		return deny(Code(err))
	}
	pk, err := wire.Payload[wire.PolicyKey](pkDoc)
	if err != nil || pk.OrgID != r.IssuerOrg {
		return deny("denied")
	}
	if wire.Verify(e.Capability, "capability", pk.PublicKey) != nil {
		return deny("invalid_signature")
	}
	if !wire.InScope(pk.Scope, r.Action, r.Resource, r.Audience) || pk.MaxTTL < 1 || pk.MaxTTL > 60 || cap.ExpiresAt-cap.IssuedAt > pk.MaxTTL {
		return deny("denied")
	}
	if !wire.Window(now, pk.NotBefore, pk.ExpiresAt) || !wire.Window(now, cap.IssuedAt, cap.ExpiresAt) {
		return deny("expired")
	}
	if cap.IssuedAt < r.IssuedAt || cap.IssuedAt < pk.NotBefore || cap.ExpiresAt > r.ExpiresAt || cap.ExpiresAt > pk.ExpiresAt {
		return deny("denied")
	}
	if cap.IssuerOrg != r.IssuerOrg || cap.AgentID != r.AgentID || cap.RuntimeKeyID != r.RuntimeKeyID || cap.DelegationID != r.DelegationID || cap.Action != r.Action || cap.Resource != r.Resource || cap.Audience != r.Audience || cap.Recipient != r.Recipient || cap.Amount != r.Amount || cap.Currency != r.Currency || cap.Asset != r.Asset || cap.Network != r.Network || cap.Nonce != r.Nonce || cap.RequestDigest != out.RequestDigest {
		return deny("request_mismatch")
	}
	if b.ActivePolicy != cap.PolicyVersion {
		return deny("policy_mismatch")
	}
	policyDoc, err := record("policy", cap.PolicyVersion)
	if err != nil {
		return deny(Code(err))
	}
	p, err := wire.Payload[wire.Policy](policyDoc)
	if err != nil || p.OrgID != r.IssuerOrg || p.Commitment != cap.PolicyCommitment || p.Currency != r.Currency || p.Asset != r.Asset || p.Network != r.Network || p.Predicate != wire.ProofProgram {
		return deny("policy_mismatch")
	}
	if !wire.Window(now, p.NotBefore, p.ExpiresAt) || cap.IssuedAt < p.NotBefore || cap.ExpiresAt > p.ExpiresAt {
		return deny("expired")
	}
	out.Trace = append(out.Trace, "delegated_capability_signature", "exact_request_binding", "active_policy_commitment")
	if r.WantProof {
		if !c.EnableZK || e.Proof == nil || e.Proof.Program != wire.ProofProgram || cap.ProofProgram != wire.ProofProgram {
			return deny("invalid_proof")
		}
		proofRequest := map[string]any{"program": wire.ProofProgram, "commitment": p.Commitment, "amount_minor_units": r.Amount, "context_digest": wire.Digest(e.Capability.Payload), "proof": e.Proof.Proof}
		data, _ := json.Marshal(proofRequest)
		req, err := http.NewRequestWithContext(ctx, "POST", c.ProofURL+"/v0/verify", bytes.NewReader(data))
		if err != nil {
			return deny("unavailable")
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := c.client().Do(req)
		if err != nil {
			return deny("unavailable")
		}
		raw, readErr := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		var answer struct {
			Valid bool `json:"valid"`
		}
		if readErr != nil || res.StatusCode != 200 || wire.Decode(raw, &answer) != nil || !answer.Valid {
			return deny("invalid_proof")
		}
		out.Trace = append(out.Trace, "hidden_limit_range_proof")
	} else if e.Proof != nil || cap.ProofProgram != "" {
		return deny("invalid_proof")
	}
	// Cap the final decision by all authenticated freshness windows.
	until := min(b.ExpiresAt, cap.ExpiresAt, r.ExpiresAt, key.ExpiresAt, d.ExpiresAt, pk.ExpiresAt, p.ExpiresAt)
	if c.now() >= until {
		return deny("expired")
	}
	out.ValidUntil = until
	out.Decision = "allow"
	out.Code = "allowed"
	out.Trace = append(out.Trace, "ready_for_counterparty_rules_and_atomic_nonce_consumption")
	return out, nil
}

func (c Config) Handler(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	var e wire.Evidence
	if err != nil || wire.Decode(raw, &e) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprint(w, `{"decision":"deny","code":"invalid_request"}`)
		return
	}
	result, err := c.Verify(r.Context(), e)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		if result.Code == "unavailable" {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(403)
		}
	}
	_ = json.NewEncoder(w).Encode(result)
}
