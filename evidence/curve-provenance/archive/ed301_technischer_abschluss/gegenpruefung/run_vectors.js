'use strict';

/*
 * Post-implementation conformance runner.
 *
 * The implementation was completed before these vector files were read.  This
 * runner consumes them only as external comparison material.  It deliberately
 * does not open the Python sources named in the vectors' provenance metadata.
 */

process.env.ED301_ENABLE_TEST_HOOKS = '1';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ed = require('./ed301.js');
const t = ed.__testOnly;
const C = ed.constants;

const positivePath = path.join(__dirname, '..', 'vektoren', 'ed301-sig-v1-positive.json');
const negativePath = path.join(__dirname, '..', 'vektoren', 'ed301-sig-v1-negative.json');
const positive = JSON.parse(fs.readFileSync(positivePath, 'utf8'));
const negative = JSON.parse(fs.readFileSync(negativePath, 'utf8'));

let checks = 0;
const positiveResults = [];
const negativeResults = [];
const internalResults = [];

function checkEqual(actual, expected, label) {
  ++checks;
  assert.equal(actual, expected, label);
}

function checkTrue(value, label) {
  ++checks;
  assert.equal(Boolean(value), true, label);
}

function bytes(hex) {
  assert.equal(typeof hex, 'string');
  assert.equal(hex.length % 2, 0);
  return Buffer.from(hex, 'hex');
}

function scalarChecks(actual, expected, id, name) {
  checkEqual(actual.toString(10), expected.decimal, `${id}: ${name} decimal`);
  checkEqual(actual.toString(16), expected.hex_be, `${id}: ${name} big-endian hex`);
  checkEqual(
    t.i2ospLE(actual, C.scalarBytes).toString('hex'),
    expected.encoding_le38_hex,
    `${id}: ${name} little-endian encoding`,
  );
}

function pointChecks(point, expected, id, name) {
  const affine = t.toAffine(point);
  checkEqual(t.encodePoint(point).toString('hex'), expected.encoding_hex, `${id}: ${name} encoding`);
  checkEqual(affine.x.toString(10), expected.x.decimal, `${id}: ${name}.x decimal`);
  checkEqual(affine.x.toString(16), expected.x.hex_be, `${id}: ${name}.x hex`);
  checkEqual(affine.y.toString(10), expected.y.decimal, `${id}: ${name}.y decimal`);
  checkEqual(affine.y.toString(16), expected.y.hex_be, `${id}: ${name}.y hex`);
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function checkPermittedSourceHash(document, relativePath) {
  const entry = document.sources.find((source) => source.path === relativePath);
  assert.ok(entry, `missing source metadata: ${relativePath}`);
  const absolute = path.join(__dirname, '..', relativePath);
  checkEqual(sha256File(absolute), entry.sha256, `source hash: ${relativePath}`);
}

checkEqual(positive.schema, 'Ed301-Sig-v1-positive-vectors-v1', 'positive schema');
checkEqual(negative.schema, 'Ed301-Sig-v1-negative-vectors-v1', 'negative schema');
checkEqual(positive.domain_hex, C.dom.toString('hex'), 'positive domain');
checkEqual(negative.domain_hex, C.dom.toString('hex'), 'negative domain');
checkEqual(Number(positive.vector_count_decimal), positive.vectors.length, 'positive count metadata');
checkEqual(
  Number(negative.verification_vector_count_decimal),
  negative.verification_vectors.length,
  'negative count metadata',
);
for (const document of [positive, negative]) {
  checkPermittedSourceHash(document, 'parameter/ed301-v1.json');
  checkPermittedSourceHash(document, 'spezifikation/Ed301-Sig-v1.md');
}

for (const vector of positive.vectors) {
  const id = vector.id;
  const input = vector.inputs;
  const seed = bytes(input.seed_hex);
  const context = bytes(input.context_hex);
  const message = bytes(input.message_hex);
  const announcedLength = BigInt(input.message_length_decimal);
  const keyExpected = vector.key_derivation;
  const nonceExpected = vector.nonce_derivation;
  const challengeExpected = vector.challenge_derivation;

  checkEqual(seed.length, 38, `${id}: seed length`);
  checkEqual(context.length.toString(), input.context_length_decimal, `${id}: context length`);
  checkEqual(BigInt(message.length).toString(), input.message_length_decimal, `${id}: message length`);

  const key = t.deriveKeyValues(seed);
  checkEqual(key.scalarRetry.toString(), keyExpected.scalar_retry_decimal, `${id}: key retry`);
  const keyFrame = t.frameKeyScalar(seed, key.scalarRetry);
  checkEqual(keyFrame.toString('hex'), keyExpected.scalar_frame_hex, `${id}: key frame`);
  checkEqual(t.shake256(keyFrame, 64).toString('hex'), keyExpected.scalar_xof64_hex, `${id}: key XOF`);
  scalarChecks(key.scalar, keyExpected.secret_scalar_s, id, 's');

  const prefixFrame = t.framePrefix(seed);
  checkEqual(prefixFrame.toString('hex'), keyExpected.prefix_frame_hex, `${id}: prefix frame`);
  checkEqual(key.prefix.toString('hex'), keyExpected.prefix_xof64_hex, `${id}: prefix XOF`);
  checkEqual(key.publicKey.toString('hex'), keyExpected.public_key_hex, `${id}: public key`);
  pointChecks(key.publicPoint, keyExpected.public_point_A, id, 'A');

  const nonceResult = t.deriveNonzero(
    (retry) => t.frameNonce(key.prefix, key.publicKey, context, message, retry),
    t.h2s,
  );
  checkEqual(nonceResult.retry.toString(), nonceExpected.nonce_retry_decimal, `${id}: nonce retry`);
  const nonceFrame = t.frameNonce(key.prefix, key.publicKey, context, message, nonceResult.retry);
  checkEqual(nonceFrame.toString('hex'), nonceExpected.nonce_frame_hex, `${id}: nonce frame`);
  checkEqual(t.shake256(nonceFrame, 64).toString('hex'), nonceExpected.nonce_xof64_hex, `${id}: nonce XOF`);
  scalarChecks(nonceResult.scalar, nonceExpected.nonce_scalar_r, id, 'r');
  const commitmentPoint = t.scalarMultiply(t.basepoint, nonceResult.scalar);
  const commitment = t.encodePoint(commitmentPoint);
  checkEqual(commitment.toString('hex'), nonceExpected.commitment_encoding_R_hex, `${id}: R encoding`);
  pointChecks(commitmentPoint, nonceExpected.commitment_point_R, id, 'R');

  const challengeFrame = t.frameChallenge(key.publicKey, context, message, commitment);
  checkEqual(challengeFrame.toString('hex'), challengeExpected.challenge_frame_hex, `${id}: challenge frame`);
  checkEqual(
    t.shake256(challengeFrame, 64).toString('hex'),
    challengeExpected.challenge_xof64_hex,
    `${id}: challenge XOF`,
  );
  const challenge = t.h2s(challengeFrame);
  scalarChecks(challenge, challengeExpected.challenge_scalar_k, id, 'k');

  const response = t.modQ(nonceResult.scalar + challenge * key.scalar);
  scalarChecks(response, vector.result.response_scalar_S, id, 'S');
  const generated = ed.sign(seed, context, announcedLength, message);
  checkEqual(generated.toString('hex'), vector.result.signature_hex, `${id}: generated signature`);
  checkEqual(generated.length.toString(), vector.result.signature_length_decimal, `${id}: signature length`);
  checkEqual(vector.result.verify, true, `${id}: expected positive flag`);
  checkTrue(ed.verify(key.publicKey, context, announcedLength, message, generated), `${id}: generated verifies`);
  checkTrue(
    ed.verify(key.publicKey, context, announcedLength, message, bytes(vector.result.signature_hex)),
    `${id}: published signature verifies`,
  );

  // A different chunk partition must produce the same transcript and bytes.
  const chunks = [];
  for (let offset = 0; offset < message.length; offset += 113) {
    chunks.push(message.subarray(offset, Math.min(message.length, offset + 113)));
  }
  if (message.length === 0) chunks.push(Buffer.alloc(0));
  const streamed = ed.signChunks(seed, context, announcedLength, chunks);
  checkEqual(streamed.toString('hex'), vector.result.signature_hex, `${id}: streamed signature`);
  checkTrue(
    ed.verifyChunks(key.publicKey, context, announcedLength, chunks, streamed),
    `${id}: streamed verification`,
  );

  positiveResults.push(id);
}

for (const vector of negative.verification_vectors) {
  const publicKey = bytes(vector.public_key_hex);
  const context = bytes(vector.context_hex);
  const message = bytes(vector.message_hex);
  const signature = bytes(vector.signature_hex);
  const announcedLength = BigInt(vector.message_length_decimal);
  const actual = ed.verify(publicKey, context, announcedLength, message, signature);
  checkEqual(actual, vector.expected_verify, `${vector.id}: verification result`);
  checkEqual(vector.expected_verify, false, `${vector.id}: vector is negative`);
  negativeResults.push(vector.id);
}

for (const vector of negative.internal_only.framing) {
  const canonical = bytes(vector.canonical_frame_hex);
  const altered = bytes(vector.altered_frame_hex);
  const canonicalXof = t.shake256(canonical, 64).toString('hex');
  const alteredXof = t.shake256(altered, 64).toString('hex');
  checkEqual(canonicalXof, vector.canonical_xof64_hex, `${vector.id}: canonical XOF`);
  checkEqual(alteredXof, vector.altered_xof64_hex, `${vector.id}: altered XOF`);
  checkTrue(!canonical.equals(altered), `${vector.id}: frames differ`);
  checkTrue(canonicalXof !== alteredXof, `${vector.id}: XOF outputs differ`);
  internalResults.push(vector.id);
}

const nullVectors = new Map(negative.internal_only.null_and_retry.map((v) => [v.id, v]));
const base = positive.vectors.find((v) => v.id === negative.base_positive_vector_id);
assert.ok(base, 'negative base vector missing');
const baseSeed = bytes(base.inputs.seed_hex);
const baseContext = bytes(base.inputs.context_hex);
const baseMessage = bytes(base.inputs.message_hex);

{
  const vector = nullVectors.get('internal-key-scalar-zero-then-one');
  const seenFrames = [];
  const xofs = vector.injected_xof64_hex.map(bytes);
  const result = t.deriveNonzero(
    (retry) => t.frameKeyScalar(baseSeed, retry),
    (frame, retry) => {
      seenFrames.push(frame.toString('hex'));
      return t.os2ipLE(xofs[retry]) % C.q;
    },
  );
  checkEqual(result.retry.toString(), vector.expected_retries_decimal, `${vector.id}: retries`);
  checkEqual(result.scalar.toString(), vector.expected_scalar_decimal, `${vector.id}: scalar`);
  checkEqual(JSON.stringify(seenFrames), JSON.stringify(vector.frame_hex), `${vector.id}: frames`);
  internalResults.push(vector.id);
}

{
  const vector = nullVectors.get('internal-nonce-zero-then-one');
  const key = t.deriveKeyValues(baseSeed);
  const seenFrames = [];
  const xofs = vector.injected_xof64_hex.map(bytes);
  const result = t.deriveNonzero(
    (retry) => t.frameNonce(key.prefix, key.publicKey, baseContext, baseMessage, retry),
    (frame, retry) => {
      seenFrames.push(frame.toString('hex'));
      return t.os2ipLE(xofs[retry]) % C.q;
    },
  );
  checkEqual(result.retry.toString(), vector.expected_retries_decimal, `${vector.id}: retries`);
  checkEqual(result.scalar.toString(), vector.expected_scalar_decimal, `${vector.id}: scalar`);
  checkEqual(JSON.stringify(seenFrames), JSON.stringify(vector.frame_hex), `${vector.id}: frames`);
  internalResults.push(vector.id);
}

{
  const vector = nullVectors.get('internal-retry-exhaustion');
  let caught = false;
  try {
    t.deriveNonzero(
      (retry) => t.frameKeyScalar(baseSeed, retry),
      () => 0n,
      Number(vector.start_retry_decimal),
    );
  } catch (error) {
    caught = /exhausted/.test(error.message);
  }
  checkTrue(caught, `${vector.id}: no wrap at u32 maximum`);
  internalResults.push(vector.id);
}

{
  const vector = nullVectors.get('internal-zero-challenge-accepted');
  const reduced = t.os2ipLE(bytes(vector.injected_xof64_hex)) % C.q;
  checkEqual(reduced.toString(), vector.expected_k_decimal, `${vector.id}: k`);
  internalResults.push(vector.id);
}

{
  const vector = nullVectors.get('internal-zero-S-accepted');
  const s = BigInt(vector.synthetic_s_decimal);
  const r = BigInt(vector.synthetic_r_decimal);
  const k = BigInt(vector.synthetic_k_decimal);
  const response = t.modQ(r + k * s);
  checkEqual(response.toString(), vector.expected_S_decimal, `${vector.id}: S`);
  checkEqual(
    t.i2ospLE(response, C.scalarBytes).toString('hex'),
    vector.expected_S_encoding_le38_hex,
    `${vector.id}: S encoding`,
  );
  internalResults.push(vector.id);
}

const result = {
  status: 'PASS',
  node: process.version,
  positive_vectors: positiveResults.length,
  negative_verification_vectors: negativeResults.length,
  internal_negative_vectors: internalResults.length,
  assertions: checks,
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
