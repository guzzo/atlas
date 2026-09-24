package wire

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPublishedVector(t *testing.T) {
	var v struct {
		PublicKey             string   `json:"public_key"`
		CanonicalPayload      string   `json:"canonical_payload"`
		CanonicalSigningInput string   `json:"canonical_signing_input"`
		PayloadDigest         string   `json:"payload_digest"`
		Document              Document `json:"document"`
	}
	raw, err := os.ReadFile("../../api/signing-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b, err := Canonical(v.Document.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != v.CanonicalPayload {
		t.Fatalf("canonical bytes differ: %s", b)
	}
	input, err := Canonical(Header{v.Document.Profile, v.Document.Kind, v.Document.KeyID, v.Document.Payload})
	if err != nil {
		t.Fatal(err)
	}
	if string(input) != v.CanonicalSigningInput {
		t.Fatal("signing input differs")
	}
	if Digest(v.Document.Payload) != v.PayloadDigest {
		t.Fatal("digest differs")
	}
	if err = Verify(v.Document, "test_vector", v.PublicKey); err != nil {
		t.Fatal(err)
	}
}
func TestRejectAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"nested":{"x":1,"\u0078":2}}`, `{"a":1} {"a":2}`, `{"a":1,}`, `{"a":NaN}`} {
		t.Run(raw, func(t *testing.T) {
			var v map[string]any
			if Decode([]byte(raw), &v) == nil {
				t.Fatal("accepted ambiguous JSON")
			}
		})
	}
}
func TestAmountsAndTime(t *testing.T) {
	r := Request{RequestID: "r", IssuerOrg: "acme", AgentID: "a", RuntimeKeyID: "k", DelegationID: "d", Nonce: "0123456789abcdef0123456789abcdef", Amount: 1, Currency: "USD", Asset: "iso4217:USD", Network: "simulation", IssuedAt: 100, ExpiresAt: 160, Body: json.RawMessage(`{}`)}
	if ValidRequest(r, 101) != nil {
		t.Fatal("valid request rejected")
	}
	r.Amount = MaxAmount + 1
	if ValidRequest(r, 101) == nil {
		t.Fatal("overflow accepted")
	}
	r.Amount = 1
	r.Currency = "usd"
	if ValidRequest(r, 101) == nil {
		t.Fatal("ambiguous units accepted")
	}
}
