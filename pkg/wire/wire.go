// Package wire defines Passport's versioned, interoperable signing profile.
package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const Profile = "passport.v0.ed25519-jcs"
const ProofProgram = "passport.hidden-limit.bp5.ristretto.32x2.v1"
const MaxAmount = uint64(4294967295)

type Document struct {
	Profile   string          `json:"profile"`
	Kind      string          `json:"kind"`
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}
type Header struct {
	Profile string          `json:"profile"`
	Kind    string          `json:"kind"`
	KeyID   string          `json:"key_id"`
	Payload json.RawMessage `json:"payload"`
}
type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RootKeyID string `json:"root_key_id"`
	PublicKey string `json:"public_key"`
	CreatedAt int64  `json:"created_at"`
}
type Agent struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
}
type RuntimeKey struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	AgentID      string `json:"agent_id"`
	PublicKey    string `json:"public_key"`
	DelegationID string `json:"delegation_id"`
	NotBefore    int64  `json:"not_before"`
	ExpiresAt    int64  `json:"expires_at"`
}
type Scope struct {
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Audiences []string `json:"audiences"`
}
type Delegation struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	AgentID      string `json:"agent_id"`
	RuntimeKeyID string `json:"runtime_key_id"`
	Scope
	NotBefore int64 `json:"not_before"`
	ExpiresAt int64 `json:"expires_at"`
}
type PolicyKey struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	PublicKey string `json:"public_key"`
	Scope
	MaxTTL    int64 `json:"max_ttl"`
	NotBefore int64 `json:"not_before"`
	ExpiresAt int64 `json:"expires_at"`
}
type Policy struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Version     int64  `json:"version"`
	Predecessor string `json:"predecessor"`
	Commitment  string `json:"commitment"`
	Predicate   string `json:"predicate"`
	Currency    string `json:"currency"`
	Asset       string `json:"asset"`
	Network     string `json:"network"`
	NotBefore   int64  `json:"not_before"`
	ExpiresAt   int64  `json:"expires_at"`
}
type Request struct {
	RequestID    string          `json:"request_id"`
	IssuerOrg    string          `json:"issuer_org"`
	AgentID      string          `json:"agent_id"`
	RuntimeKeyID string          `json:"runtime_key_id"`
	DelegationID string          `json:"delegation_id"`
	Action       string          `json:"action"`
	Resource     string          `json:"resource"`
	Audience     string          `json:"audience"`
	Recipient    string          `json:"recipient"`
	Amount       uint64          `json:"amount_minor_units"`
	Currency     string          `json:"currency"`
	Asset        string          `json:"asset"`
	Network      string          `json:"network"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	Body         json.RawMessage `json:"body"`
	Nonce        string          `json:"nonce"`
	IssuedAt     int64           `json:"issued_at"`
	ExpiresAt    int64           `json:"expires_at"`
	WantProof    bool            `json:"want_proof"`
}
type Capability struct {
	CapabilityID     string `json:"capability_id"`
	IssuerOrg        string `json:"issuer_org"`
	AgentID          string `json:"agent_id"`
	RuntimeKeyID     string `json:"runtime_key_id"`
	DelegationID     string `json:"delegation_id"`
	Action           string `json:"action"`
	Resource         string `json:"resource"`
	Audience         string `json:"audience"`
	Recipient        string `json:"recipient"`
	Amount           uint64 `json:"amount_minor_units"`
	Currency         string `json:"currency"`
	Asset            string `json:"asset"`
	Network          string `json:"network"`
	RequestDigest    string `json:"request_digest"`
	Nonce            string `json:"nonce"`
	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"`
	PolicyVersion    string `json:"policy_version"`
	PolicyCommitment string `json:"policy_commitment"`
	ProofProgram     string `json:"proof_program"`
}
type Proof struct {
	Program string `json:"program"`
	Proof   string `json:"proof"`
}
type Evidence struct {
	Request    Document `json:"request"`
	Delegation Document `json:"delegation"`
	Capability Document `json:"capability"`
	Proof      *Proof   `json:"proof,omitempty"`
}
type Root struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
}
type Record struct {
	Document Document `json:"document"`
	Revoked  bool     `json:"revoked"`
}
type Bundle struct {
	OrgID        string   `json:"org_id"`
	Challenge    string   `json:"challenge"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at"`
	ActivePolicy string   `json:"active_policy"`
	Roots        []Root   `json:"roots"`
	Records      []Record `json:"records"`
}
type Revocation struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	TargetKind string `json:"target_kind"`
	TargetID   string `json:"target_id"`
	IssuedAt   int64  `json:"issued_at"`
}
type Rotation struct {
	ID            string `json:"id"`
	OrgID         string `json:"org_id"`
	PreviousKeyID string `json:"previous_key_id"`
	PublicKey     string `json:"public_key"`
	IssuedAt      int64  `json:"issued_at"`
}
type Receipt struct {
	ID             string   `json:"id"`
	ReceiptType    string   `json:"receipt_type"`
	OrgID          string   `json:"org_id"`
	Decision       string   `json:"decision"`
	Code           string   `json:"code"`
	RequestID      string   `json:"request_id"`
	CapabilityID   string   `json:"capability_id"`
	Verifier       string   `json:"verifier"`
	IssuedAt       int64    `json:"issued_at"`
	PolicyVersion  string   `json:"policy_version"`
	RequestDigest  string   `json:"request_digest"`
	EvidenceDigest string   `json:"evidence_digest"`
	Trace          []string `json:"trace"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,127}$`)

func ID(s string) bool { return identifier.MatchString(s) }
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

// Decode rejects duplicate keys, unknown struct fields, and trailing data.
func Decode(raw []byte, v any) error {
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func Payload[T any](d Document) (T, error) { var p T; err := Decode(d.Payload, &p); return p, err }
func Digest(v any) string {
	b, err := Canonical(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func PublicKey(encoded string) (ed25519.PublicKey, error) {
	der, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	v, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := v.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("only Ed25519 is supported")
	}
	return key, nil
}
func Sign(kind, keyID string, payload any, key ed25519.PrivateKey) (Document, error) {
	p, err := Canonical(payload)
	if err != nil {
		return Document{}, err
	}
	h := Header{Profile, kind, keyID, p}
	b, err := Canonical(h)
	if err != nil {
		return Document{}, err
	}
	return Document{Profile, kind, keyID, p, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b))}, nil
}
func Verify(d Document, kind, public string) error {
	if d.Profile != Profile || d.Kind != kind || !ID(d.KeyID) {
		return errors.New("invalid signing profile or kind")
	}
	key, err := PublicKey(public)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(d.Signature)
	if err != nil {
		return err
	}
	b, err := Canonical(Header{d.Profile, d.Kind, d.KeyID, d.Payload})
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("invalid signature")
	}
	return nil
}
func InScope(s Scope, action, resource, audience string) bool {
	contains := func(xs []string, s string) bool {
		for _, x := range xs {
			if x == s {
				return true
			}
		}
		return false
	}
	return contains(s.Actions, action) && contains(s.Resources, resource) && contains(s.Audiences, audience)
}
func Window(now, from, to int64) bool { return from > 0 && from <= now && now < to }
func ValidRequest(r Request, now int64) error {
	if !ID(r.RequestID) || !ID(r.IssuerOrg) || !ID(r.AgentID) || !ID(r.RuntimeKeyID) || !ID(r.DelegationID) || !ID(r.Nonce) {
		return errors.New("invalid identifier")
	}
	if r.Amount == 0 || r.Amount > MaxAmount || r.Currency != "USD" || r.Asset != "iso4217:USD" || r.Network != "simulation" {
		return errors.New("invalid amount or units")
	}
	if len(r.Nonce) < 32 || r.ExpiresAt-r.IssuedAt > 120 || !Window(now, r.IssuedAt, r.ExpiresAt) {
		return fmt.Errorf("invalid request window")
	}
	if len(r.Body) == 0 || bytes.Equal(r.Body, []byte("null")) {
		return errors.New("missing body")
	}
	return nil
}
