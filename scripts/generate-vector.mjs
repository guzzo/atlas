import { createPrivateKey, createPublicKey, sign, createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import canonicalize from 'canonicalize';
// Public, deterministic test seed from RFC 8032, never used by the running app.
const key = createPrivateKey({
  key: Buffer.from(
    '302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'hex',
  ),
  format: 'der',
  type: 'pkcs8',
});
const payload = {
  issuer_org: 'acme',
  amount_minor_units: 1200,
  currency: 'USD',
  body: { z: 'line\nquote"', a: 'café 🛂' },
  issued_at: 1800000000,
};
const header = {
  profile: 'passport.v0.ed25519-jcs',
  kind: 'test_vector',
  key_id: 'rfc8032-test-only',
  payload,
};
const vector = {
  description:
    'Public test material only. RFC 8032 seed; RFC 8785 canonicalization; never a development or production identity.',
  public_key: createPublicKey(key).export({ format: 'der', type: 'spki' }).toString('base64url'),
  canonical_payload: canonicalize(payload),
  canonical_signing_input: canonicalize(header),
  payload_digest: createHash('sha256').update(canonicalize(payload)).digest('hex'),
  document: {
    ...header,
    signature: sign(null, Buffer.from(canonicalize(header)), key).toString('base64url'),
  },
};
await writeFile('api/signing-vectors.json', JSON.stringify(vector, null, 2) + '\n');
