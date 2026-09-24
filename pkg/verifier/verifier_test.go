package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/passport-local/atlas/pkg/wire"
)

type fixture struct {
	t                               *testing.T
	c                               Config
	e                               wire.Evidence
	b                               wire.Bundle
	root, runtime, policy, registry ed25519.PrivateKey
	status                          int
	badChallenge                    bool
}

func pair() (string, ed25519.PrivateKey) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return base64.RawURLEncoding.EncodeToString(der), key
}
func (f *fixture) sign(kind, id string, payload any, key ed25519.PrivateKey) wire.Document {
	d, err := wire.Sign(kind, id, payload, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}
func setup(t *testing.T) *fixture {
	f := &fixture{t: t, status: 200}
	rootPublic, root := pair()
	runtimePublic, runtime := pair()
	policyPublic, policy := pair()
	registryPublic, registry := pair()
	f.root = root
	f.runtime = runtime
	f.policy = policy
	f.registry = registry
	f.c = Config{Audience: "globex", Pins: Pins{RegistryKeyID: "registry", RegistryPublicKey: registryPublic, TrustedRoots: map[string]map[string]string{"acme": {"root": rootPublic}}}, Now: func() time.Time { return time.Unix(1000, 0) }}
	f.b = wire.Bundle{OrgID: "acme", IssuedAt: 1000, ExpiresAt: 1005, ActivePolicy: "policy-1", Roots: []wire.Root{{KeyID: "root", PublicKey: rootPublic}}}
	scope := wire.Scope{Actions: []string{"purchase"}, Resources: []string{"globex:research-report"}, Audiences: []string{"globex"}}
	docs := []struct {
		kind    string
		payload any
	}{
		{"organization", wire.Organization{ID: "acme", Name: "Acme", RootKeyID: "root", PublicKey: rootPublic, CreatedAt: 900}},
		{"agent", wire.Agent{ID: "agent", OrgID: "acme", Name: "Agent", CreatedAt: 900}},
		{"runtime_key", wire.RuntimeKey{ID: "runtime", OrgID: "acme", AgentID: "agent", PublicKey: runtimePublic, DelegationID: "delegation", NotBefore: 900, ExpiresAt: 2000}},
		{"delegation", wire.Delegation{ID: "delegation", OrgID: "acme", AgentID: "agent", RuntimeKeyID: "runtime", Scope: scope, NotBefore: 900, ExpiresAt: 2000}},
		{"policy_key", wire.PolicyKey{ID: "policy-key", OrgID: "acme", PublicKey: policyPublic, Scope: scope, MaxTTL: 60, NotBefore: 900, ExpiresAt: 2000}},
		{"policy", wire.Policy{ID: "policy-1", OrgID: "acme", Version: 1, Commitment: strings.Repeat("ab", 32), Predicate: wire.ProofProgram, Currency: "USD", Asset: "iso4217:USD", Network: "simulation", NotBefore: 900, ExpiresAt: 2000}},
	}
	for _, doc := range docs {
		d := f.sign(doc.kind, "root", doc.payload, root)
		f.b.Records = append(f.b.Records, wire.Record{Document: d})
		if doc.kind == "delegation" {
			f.e.Delegation = d
		}
	}
	r := wire.Request{RequestID: "request", IssuerOrg: "acme", AgentID: "agent", RuntimeKeyID: "runtime", DelegationID: "delegation", Action: "purchase", Resource: "globex:research-report", Audience: "globex", Recipient: "globex", Amount: 1200, Currency: "USD", Asset: "iso4217:USD", Network: "simulation", Method: "POST", Path: "/v0/purchases", Body: json.RawMessage(`{"sku":"research-report"}`), Nonce: strings.Repeat("a", 64), IssuedAt: 999, ExpiresAt: 1060}
	f.e.Request = f.sign("request", "runtime", r, runtime)
	cap := wire.Capability{CapabilityID: "cap", IssuerOrg: r.IssuerOrg, AgentID: r.AgentID, RuntimeKeyID: r.RuntimeKeyID, DelegationID: r.DelegationID, Action: r.Action, Resource: r.Resource, Audience: r.Audience, Recipient: r.Recipient, Amount: r.Amount, Currency: r.Currency, Asset: r.Asset, Network: r.Network, RequestDigest: wire.Digest(r), Nonce: r.Nonce, IssuedAt: 1000, ExpiresAt: 1060, PolicyVersion: "policy-1", PolicyCommitment: strings.Repeat("ab", 32)}
	f.e.Capability = f.sign("capability", "policy-key", cap, policy)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.status != 200 {
			w.WriteHeader(f.status)
			return
		}
		b := f.b
		b.Challenge = r.URL.Query().Get("challenge")
		if f.badChallenge {
			b.Challenge = "wrong"
		}
		json.NewEncoder(w).Encode(f.sign("trust_bundle", "registry", b, registry))
	}))
	t.Cleanup(server.Close)
	f.c.RegistryURL = server.URL
	return f
}
func (f *fixture) request(fn func(*wire.Request)) {
	r, err := wire.Payload[wire.Request](f.e.Request)
	if err != nil {
		f.t.Fatal(err)
	}
	fn(&r)
	f.e.Request = f.sign("request", "runtime", r, f.runtime)
}
func (f *fixture) capability(fn func(*wire.Capability)) {
	c, err := wire.Payload[wire.Capability](f.e.Capability)
	if err != nil {
		f.t.Fatal(err)
	}
	fn(&c)
	f.e.Capability = f.sign("capability", "policy-key", c, f.policy)
}
func TestVerificationAdversarialCases(t *testing.T) {
	cases := []struct {
		name, code string
		mutate     func(*fixture)
	}{
		{"allowed", "allowed", func(f *fixture) {}},
		{"wrong audience", "denied", func(f *fixture) { f.request(func(r *wire.Request) { r.Audience = "mallory" }) }},
		{"untrusted issuer", "untrusted_issuer", func(f *fixture) { f.request(func(r *wire.Request) { r.IssuerOrg = "mallory" }) }},
		{"changed unsigned body", "invalid_signature", func(f *fixture) {
			var r map[string]any
			json.Unmarshal(f.e.Request.Payload, &r)
			r["body"] = map[string]any{"sku": "secrets"}
			f.e.Request.Payload, _ = json.Marshal(r)
		}},
		{"changed signed body", "request_mismatch", func(f *fixture) { f.request(func(r *wire.Request) { r.Body = json.RawMessage(`{"sku":"secrets"}`) }) }},
		{"changed amount", "request_mismatch", func(f *fixture) { f.capability(func(c *wire.Capability) { c.Amount++ }) }},
		{"changed recipient", "request_mismatch", func(f *fixture) { f.capability(func(c *wire.Capability) { c.Recipient = "mallory" }) }},
		{"changed nonce", "request_mismatch", func(f *fixture) { f.capability(func(c *wire.Capability) { c.Nonce = strings.Repeat("b", 64) }) }},
		{"expired capability", "expired", func(f *fixture) { f.capability(func(c *wire.Capability) { c.ExpiresAt = 1000 }) }},
		{"expired request", "expired", func(f *fixture) { f.request(func(r *wire.Request) { r.ExpiresAt = 1000 }) }},
		{"future request", "expired", func(f *fixture) { f.request(func(r *wire.Request) { r.IssuedAt = 1001 }) }},
		{"excess capability lifetime", "denied", func(f *fixture) { f.capability(func(c *wire.Capability) { c.ExpiresAt = 1061 }) }},
		{"stale policy", "policy_mismatch", func(f *fixture) { f.b.ActivePolicy = "policy-2" }},
		{"changed commitment", "policy_mismatch", func(f *fixture) {
			f.capability(func(c *wire.Capability) { c.PolicyCommitment = strings.Repeat("cd", 32) })
		}},
		{"registry unavailable", "unavailable", func(f *fixture) { f.status = 503 }},
		{"registry replayed challenge", "stale_state", func(f *fixture) { f.badChallenge = true }},
		{"stale state", "stale_state", func(f *fixture) { f.b.IssuedAt = 990; f.b.ExpiresAt = 995 }},
		{"excess state lifetime", "stale_state", func(f *fixture) { f.b.ExpiresAt = 1006 }},
		{"revoked root", "revoked", func(f *fixture) { f.b.Roots[0].Revoked = true }},
		{"unrecognized root", "untrusted_issuer", func(f *fixture) { delete(f.c.Pins.TrustedRoots["acme"], "root") }},
		{"unrecognized algorithm", "invalid_signature", func(f *fixture) { f.e.Request.Profile = "passport.rs256" }},
		{"substituted delegation", "invalid_signature", func(f *fixture) { f.e.Delegation.Signature = strings.Repeat("A", 86) }},
		{"zero amount", "invalid_request", func(f *fixture) { f.request(func(r *wire.Request) { r.Amount = 0 }) }},
		{"ambiguous units", "invalid_request", func(f *fixture) { f.request(func(r *wire.Request) { r.Asset = "USD" }) }},
		{"proof downgrade", "invalid_proof", func(f *fixture) {
			f.request(func(r *wire.Request) { r.WantProof = true })
			f.capability(func(c *wire.Capability) {
				c.RequestDigest = wire.Digest(f.e.Request.Payload)
				c.ProofProgram = wire.ProofProgram
			})
		}},
		{"unexpected proof", "invalid_proof", func(f *fixture) { f.e.Proof = &wire.Proof{Program: wire.ProofProgram, Proof: "00"} }},
	}
	for _, kind := range []string{"organization", "agent", "runtime_key", "delegation", "policy_key", "policy"} {
		cases = append(cases, struct {
			name, code string
			mutate     func(*fixture)
		}{"revoked " + kind, "revoked", func(f *fixture) {
			for i := range f.b.Records {
				if f.b.Records[i].Document.Kind == kind {
					f.b.Records[i].Revoked = true
				}
			}
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			tc.mutate(f)
			result, err := f.c.Verify(context.Background(), f.e)
			if result.Code != tc.code {
				t.Fatalf("wanted %s, got %s (%v)", tc.code, result.Code, err)
			}
			if tc.code == "allowed" {
				if err != nil || result.ValidUntil != 1005 {
					t.Fatalf("bad success: %+v %v", result, err)
				}
			} else if err == nil || result.Decision != "deny" {
				t.Fatal("must fail closed")
			}
		})
	}
}
func TestStateExpiryDuringVerification(t *testing.T) {
	f := setup(t)
	calls := 0
	f.c.Now = func() time.Time {
		calls++
		if calls > 2 {
			return time.Unix(1005, 0)
		}
		return time.Unix(1000, 0)
	}
	result, err := f.c.Verify(context.Background(), f.e)
	if err == nil || result.Code != "expired" {
		t.Fatalf("stale final decision: %+v", result)
	}
}
