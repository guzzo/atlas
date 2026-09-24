import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { canonical, digest, keys, sign, strictJSON, verify } from '../sdk/wire.js';

test('signature authenticates kind, key ID and every payload field', () => {
  const k = keys(),
    doc = sign(
      'test',
      'key-1',
      { amount_minor_units: 1200, body: { resource: 'report' } },
      k.private_key,
    );
  assert.equal(verify(doc, 'test', k.public_key).amount_minor_units, 1200);
  for (const changed of [
    { ...doc, key_id: 'key-2' },
    { ...doc, kind: 'capability' },
    { ...doc, payload: { ...doc.payload, amount_minor_units: 1201 } },
  ])
    assert.throws(() => verify(changed, 'test', k.public_key));
});
test('canonicalization rejects duplicate JSON keys recursively and accepts Unicode', () => {
  assert.throws(() => strictJSON('{"a":1,"a":2}'));
  assert.throws(() => strictJSON('{"nested":{"x":1,"\\u0078":2}}'));
  assert.throws(() => strictJSON('{"a":1,}'));
  assert.throws(() => strictJSON('{/* comment */"a":1}'));
  assert.equal(canonical({ b: 2, a: 'é' }), '{"a":"é","b":2}');
});
test('published canonicalization and Ed25519 vector', async () => {
  const v = JSON.parse(await readFile('api/signing-vectors.json', 'utf8'));
  assert.equal(canonical(v.document.payload), v.canonical_payload);
  assert.equal(digest(v.document.payload), v.payload_digest);
  assert.deepEqual(verify(v.document, 'test_vector', v.public_key), v.document.payload);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const last = alphabet.indexOf(v.document.signature.at(-1));
  const alias = {
    ...v.document,
    signature: v.document.signature.slice(0, -1) + alphabet[last + 1],
  };
  assert.deepEqual(
    Buffer.from(alias.signature, 'base64url'),
    Buffer.from(v.document.signature, 'base64url'),
  );
  assert.throws(
    () => verify(alias, 'test_vector', v.public_key),
    'noncanonical base64url must be rejected',
  );
});
