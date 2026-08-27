'use strict';

/*
 * Post-implementation X301-v1 conformance runner.
 *
 * x301.js and test_independent.js were complete, passing, and hash-recorded
 * before these vector JSON files were first opened.  This runner never opens
 * the Python paths mentioned by vector provenance metadata.
 */

process.env.X301_ENABLE_TEST_HOOKS = '1';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const x301 = require('./x301.js');
const t = x301.__testOnly;
const C = x301.constants;

const positivePath = path.join(__dirname, '..', '..', 'vektoren', 'x301-v1-positive.json');
const negativePath = path.join(__dirname, '..', '..', 'vektoren', 'x301-v1-negative.json');
const positive = JSON.parse(fs.readFileSync(positivePath, 'utf8'));
const negative = JSON.parse(fs.readFileSync(negativePath, 'utf8'));

let assertions = 0;

function checkEqual(actual, expected, label) {
  ++assertions;
  assert.equal(actual, expected, label);
}

function checkTrue(value, label) {
  ++assertions;
  assert.equal(Boolean(value), true, label);
}

function checkDeep(actual, expected, label) {
  ++assertions;
  assert.deepEqual(actual, expected, label);
}

function bytes(hex) {
  assert.equal(typeof hex, 'string');
  assert.equal(hex.length % 2, 0);
  return Buffer.from(hex, 'hex');
}

function mod(value) {
  const reduced = value % C.p;
  return reduced >= 0n ? reduced : reduced + C.p;
}

function scalarObject(value, expected, label) {
  checkEqual(value.toString(10), expected.decimal, `${label}: decimal`);
  checkEqual(value.toString(16), expected.hex_be, `${label}: big-endian hex`);
  checkEqual(t.i2ospLE38(value).toString('hex'), expected.encoding_le38_hex, `${label}: LE38`);
}

function fieldObject(value, expected, label, requireEncoding = false) {
  checkEqual(value.toString(10), expected.decimal, `${label}: decimal`);
  checkEqual(value.toString(16), expected.hex_be, `${label}: big-endian hex`);
  if (requireEncoding || Object.hasOwn(expected, 'encoding_le38_hex')) {
    checkEqual(t.encodeU(value).toString('hex'), expected.encoding_le38_hex, `${label}: LE38`);
  }
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function checkPermittedSourceHash(document, relativePath) {
  const source = document.sources.find((entry) => entry.path === relativePath);
  checkTrue(source !== undefined, `source metadata exists: ${relativePath}`);
  checkEqual(
    sha256File(path.join(__dirname, '..', '..', relativePath)),
    source.sha256,
    `source hash: ${relativePath}`,
  );
}

checkEqual(positive.schema, 'X301-v1-positive-vectors-v1', 'positive schema');
checkEqual(negative.schema, 'X301-v1-negative-vectors-v1', 'negative schema');
checkEqual(positive.suite, 'X301-v1', 'positive suite');
checkEqual(negative.suite, 'X301-v1', 'negative suite');
checkEqual(Number(positive.positive_vector_count_decimal), positive.vectors.length, 'positive count');
checkEqual(Number(positive.agreement_pair_count_decimal), positive.agreement_pairs.length, 'agreement count');
checkEqual(Number(negative.api_vector_count_decimal), negative.api_vectors.length, 'negative API count');
checkEqual(
  Number(negative.outer_parser_vector_count_decimal),
  negative.outer_parser_vectors.length,
  'outer-parser count',
);

for (const document of [positive, negative]) {
  for (const source of [
    'parameter/ed301-v1.json',
    'spezifikation/ED301-v1.md',
    'spezifikation/X301-v1.md',
  ]) checkPermittedSourceHash(document, source);
}

const clamp = positive.clamp_analysis;
checkEqual(clamp.variable_bit_count_decimal, '298', 'clamp variable-bit count');
checkEqual(clamp.ignored_raw_bit_count_decimal, '6', 'clamp ignored-bit count');
checkEqual(clamp.raw_preimage_count_decimal, '64', 'clamp raw-preimage count');
checkDeep(
  clamp.ignored_or_overwritten_raw_bit_positions,
  [0, 1, 300, 301, 302, 303],
  'clamp ignored positions',
);
checkDeep(clamp.variable_bit_positions, [2, 299], 'clamp variable range');
checkEqual(clamp.variable_bit_flip_deltas_decimal.length, 298, 'variable delta count');
for (let index = 0; index < 298; ++index) {
  checkEqual(
    clamp.variable_bit_flip_deltas_decimal[index],
    (1n << BigInt(index + 2)).toString(),
    `variable delta bit ${index + 2}`,
  );
}

const minimumSecret = bytes(clamp.minimum_clamp.raw_secret_hex);
const minimum = t.decodeScalarDetailed(minimumSecret);
checkEqual(minimum.clamped.toString('hex'), clamp.minimum_clamp.clamped_bytes_hex, 'minimum clamp bytes');
scalarObject(minimum.scalar, clamp.minimum_clamp.k, 'minimum scalar');
checkEqual(minimum.scalar, 1n << 300n, 'minimum scalar formula');

const maximumSecret = bytes(clamp.maximum_clamp.raw_secret_hex);
const maximum = t.decodeScalarDetailed(maximumSecret);
checkEqual(maximum.clamped.toString('hex'), clamp.maximum_clamp.clamped_bytes_hex, 'maximum clamp bytes');
scalarObject(maximum.scalar, clamp.maximum_clamp.k, 'maximum scalar');
checkEqual(maximum.scalar, (1n << 301n) - 4n, 'maximum scalar formula');

const commonScalar = BigInt(clamp.common_scalar_k.decimal);
scalarObject(commonScalar, clamp.common_scalar_k, 'common scalar');
checkEqual(clamp.raw_preimages_hex.length, 64, 'common preimage list length');
checkEqual(new Set(clamp.raw_preimages_hex).size, 64, 'common preimages unique');
for (let index = 0; index < clamp.raw_preimages_hex.length; ++index) {
  const secret = bytes(clamp.raw_preimages_hex[index]);
  const decoded = t.decodeScalarDetailed(secret);
  checkEqual(decoded.scalar, commonScalar, `common preimage ${index}: scalar`);
  checkEqual(decoded.clamped.toString('hex'), clamp.common_clamped_bytes_hex, `common preimage ${index}: bytes`);
  checkEqual(x301.publicKey(secret).toString('hex'), clamp.common_public_hex, `common preimage ${index}: Public`);
}

const positiveById = new Map();
for (const vector of positive.vectors) {
  const label = vector.id;
  checkTrue(!positiveById.has(label), `${label}: unique id`);
  positiveById.set(label, vector);
  checkEqual(vector.expected, 'success', `${label}: expected success`);

  const secret = bytes(vector.secret_input_hex);
  const decoded = t.decodeScalarDetailed(secret);
  checkEqual(decoded.clamped.toString('hex'), vector.clamped_scalar_bytes_hex, `${label}: clamped bytes`);
  scalarObject(decoded.scalar, vector.scalar_k, `${label}: scalar`);

  const inputU = BigInt(vector.input_u.decimal);
  fieldObject(inputU, vector.input_u, `${label}: input u`, true);
  checkEqual(t.decodeU(bytes(vector.input_u.encoding_le38_hex)), inputU, `${label}: input u decode`);

  const ladder = t.ladder301(decoded.scalar, inputU);
  checkEqual(ladder.iterations.toString(), vector.ladder.iteration_count_decimal, `${label}: iterations`);
  fieldObject(ladder.X, vector.ladder.projective_X, `${label}: projective X`);
  fieldObject(ladder.Z, vector.ladder.projective_Z, `${label}: projective Z`);
  const output = t.finalizeProjective(ladder.X, ladder.Z);
  const affine = t.decodeU(output);
  fieldObject(affine, vector.ladder.affine_u, `${label}: affine u`, true);
  checkEqual(output.toString('hex'), vector.output_encoding_hex, `${label}: output bytes`);

  let apiOutput;
  if (vector.operation === 'Public') {
    checkEqual(inputU, C.baseU, `${label}: Public uses base u`);
    apiOutput = x301.publicKey(secret);
  } else if (vector.operation === 'Shared') {
    apiOutput = x301.shared(secret, bytes(vector.input_u.encoding_le38_hex));
  } else if (vector.operation === 'X301') {
    apiOutput = x301.x301(secret, bytes(vector.input_u.encoding_le38_hex));
  } else {
    throw new Error(`${label}: unknown operation ${vector.operation}`);
  }
  checkEqual(apiOutput.toString('hex'), vector.output_encoding_hex, `${label}: API output`);

  const cross = vector.independent_crosscheck;
  checkEqual(cross.matches_ladder, true, `${label}: crosscheck flag`);
  const crossInputU = BigInt(cross.input_point_u.decimal);
  fieldObject(crossInputU, cross.input_point_u, `${label}: cross input u`);
  checkEqual(crossInputU, inputU, `${label}: cross input agrees`);
  const crossV = BigInt(cross.input_point_v_even.decimal);
  fieldObject(crossV, cross.input_point_v_even, `${label}: cross v`);
  checkEqual(crossV & 1n, 0n, `${label}: selected v is even`);
  const coefficientC = BigInt(cross.model_coefficient_C.decimal);
  fieldObject(coefficientC, cross.model_coefficient_C, `${label}: model C`);
  const expectedC = cross.model === 'main'
    ? BigInt(require('../../parameter/ed301-v1.json').montgomery.B_decimal)
    : mod(2n * BigInt(require('../../parameter/ed301-v1.json').montgomery.B_decimal));
  checkEqual(coefficientC, expectedC, `${label}: model coefficient`);
  checkEqual(
    mod(coefficientC * crossV * crossV),
    mod(inputU * inputU * inputU + C.A * inputU * inputU + inputU),
    `${label}: independent input point equation`,
  );
  const crossResult = BigInt(cross.result_u.decimal);
  fieldObject(crossResult, cross.result_u, `${label}: cross result`, true);
  checkEqual(crossResult, affine, `${label}: cross result agrees`);
  if (cross.additional_edwards_result_u !== undefined) {
    const additional = BigInt(cross.additional_edwards_result_u.decimal);
    fieldObject(additional, cross.additional_edwards_result_u, `${label}: Edwards result`, true);
    checkEqual(additional, affine, `${label}: Edwards result agrees`);
  }
}

for (const agreement of positive.agreement_pairs) {
  const forward = positiveById.get(agreement.a_to_b_vector);
  const reverse = positiveById.get(agreement.b_to_a_vector);
  checkTrue(forward !== undefined, `${agreement.id}: forward exists`);
  checkTrue(reverse !== undefined, `${agreement.id}: reverse exists`);
  checkEqual(forward.operation, 'Shared', `${agreement.id}: forward Shared`);
  checkEqual(reverse.operation, 'Shared', `${agreement.id}: reverse Shared`);
  checkEqual(forward.output_encoding_hex, agreement.shared_encoding_hex, `${agreement.id}: forward output`);
  checkEqual(reverse.output_encoding_hex, agreement.shared_encoding_hex, `${agreement.id}: reverse output`);
}

function vectorValue(description) {
  if (description.type === 'bytes') return description.hex === null ? null : bytes(description.hex);
  if (description.type === 'str') return description.hex;
  throw new Error(`unsupported vector type ${description.type}`);
}

const stageToCode = Object.freeze({
  'secret-length': 'secret-length',
  'secret-type': 'secret-type',
  'decode-scalar-Nt': 'secret-nt',
  'u-length': 'u-length',
  'u-type': 'u-type',
  'decode-u-reserved-bits': 'u-reserved-bits',
  'decode-u-range': 'u-noncanonical',
  'ladder-Z-zero': 'ladder-infinity',
});

for (const vector of negative.api_vectors) {
  checkEqual(vector.expected, 'FAIL', `${vector.id}: expected FAIL`);
  const secret = vectorValue(vector.secret);
  const u = vectorValue(vector.u_input);
  let error = null;
  let output;
  try {
    output = vector.operation === 'Public'
      ? x301.publicKey(secret)
      : x301.shared(secret, u);
  } catch (caught) {
    error = caught;
  }
  checkEqual(output, undefined, `${vector.id}: no output`);
  checkTrue(error instanceof x301.X301Error, `${vector.id}: X301 error`);
  checkEqual(error.code, stageToCode[vector.rejection_stage], `${vector.id}: rejection stage`);
}

const ntProof = negative.excluded_Nt_preimage_proof;
scalarObject(C.twistOrder, ntProof.N_t, 'excluded Nt');
checkEqual(ntProof.raw_preimage_count_decimal, '64', 'Nt preimage count metadata');
checkEqual(ntProof.raw_preimages_hex.length, 64, 'Nt preimage list length');
checkEqual(new Set(ntProof.raw_preimages_hex).size, 64, 'Nt preimages unique');
for (let index = 0; index < ntProof.raw_preimages_hex.length; ++index) {
  let code = null;
  try {
    t.decodeScalar(bytes(ntProof.raw_preimages_hex[index]));
  } catch (error) {
    code = error.code;
  }
  checkEqual(code, 'secret-nt', `Nt preimage ${index}: rejected`);
}
for (const id of ntProof.ordinary_negative_vector_ids) {
  checkTrue(negative.api_vectors.some((vector) => vector.id === id), `Nt ordinary vector exists: ${id}`);
}

{
  const vector = negative.internal_only.all_zero_rejection;
  checkEqual(vector.injected_ladder_affine_u_decimal, '0', `${vector.id}: injected u`);
  let code = null;
  try {
    t.finalizeProjective(0n, 1n);
  } catch (error) {
    code = error.code;
  }
  checkEqual(code, 'all-zero-output', `${vector.id}: rejection`);
}

{
  const vector = negative.internal_only.keygen_retry;
  let draw = 0;
  const draws = vector.random_draws_hex.map(bytes);
  const result = x301.keyGen(() => draws[draw++]);
  checkEqual(draw.toString(), vector.expected_draw_count_decimal, `${vector.id}: draw count`);
  checkEqual(result.secretKey.toString('hex'), vector.expected_secret_hex, `${vector.id}: secret`);
  checkEqual(result.publicKey.toString('hex'), vector.expected_public_hex, `${vector.id}: public`);
}

function outerDispatch(suite, version, secret, u) {
  if (suite !== 'X301-v1') throw new Error('outer-parser-suite-selection');
  if (version !== 1n) throw new Error('outer-parser-version-selection');
  return x301.x301(secret, u);
}

for (const vector of negative.outer_parser_vectors) {
  checkEqual(vector.expected, 'FAIL-before-X301', `${vector.id}: expected outer failure`);
  let stage = null;
  try {
    outerDispatch(
      vector.suite,
      BigInt(vector.version_decimal),
      bytes(vector.secret_hex),
      bytes(vector.u_hex),
    );
  } catch (error) {
    stage = error.message;
  }
  checkEqual(stage, vector.rejection_stage, `${vector.id}: outer rejection stage`);
}

const result = {
  status: 'PASS',
  node: process.version,
  positive_vectors: positive.vectors.length,
  agreement_pairs: positive.agreement_pairs.length,
  negative_api_vectors: negative.api_vectors.length,
  negative_outer_parser_vectors: negative.outer_parser_vectors.length,
  internal_negative_vectors: 2,
  clamp_common_preimages: clamp.raw_preimages_hex.length,
  excluded_Nt_preimages: ntProof.raw_preimages_hex.length,
  assertions,
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

