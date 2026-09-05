'use strict';

/*
 * ED301 / Ed301-Sig-v1 independent Node.js counter-implementation.
 *
 * NOT FOR PRODUCTION.  This deliberately straightforward BigInt code is not
 * constant-time and has not been audited for side channels or fault attacks.
 *
 * Independence rule: this file was written only from parameter/ed301-v1.json
 * and spezifikation/Ed301-Sig-v1.md.  It does not import or reproduce either
 * Python reference implementation or their tests.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PARAMETER_PATH = path.join(__dirname, '..', 'parameter', 'ed301-v1.json');
const parameters = JSON.parse(fs.readFileSync(PARAMETER_PATH, 'utf8'));

const P = BigInt(parameters.field.p_decimal);
const A_COEFF = BigInt(parameters.edwards.a_decimal);
const D_COEFF = BigInt(parameters.edwards.d_decimal);
const Q = BigInt(parameters.group.q_decimal);
const FIELD_BYTES = parameters.encoding.field_bytes;
const SCALAR_BYTES = parameters.encoding.scalar_bytes;
const POINT_BYTES = parameters.encoding.point_bytes;
const SIGNATURE_BYTES = 2 * POINT_BYTES;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U32 = 0xffffffff;

const DOM = Buffer.from('0c45643330312d5369672d76310100', 'hex');
const BASEPOINT_ENCODING = Buffer.from(parameters.basepoint.G_compressed_edwards_hex, 'hex');

const OP_KEY_SCALAR = 0x01;
const OP_NONCE_PREFIX = 0x02;
const OP_NONCE = 0x03;
const OP_CHALLENGE = 0x04;

const TAG_SEED = 0x01;
const TAG_RETRY = 0x02;
const TAG_PREFIX = 0x03;
const TAG_PUBLIC_KEY = 0x04;
const TAG_CONTEXT = 0x05;
const TAG_MESSAGE = 0x06;
const TAG_COMMITMENT_R = 0x07;

function mod(x) {
  const r = x % P;
  return r >= 0n ? r : r + P;
}

function modQ(x) {
  const r = x % Q;
  return r >= 0n ? r : r + Q;
}

function powMod(base, exponent, modulus = P) {
  if (exponent < 0n) throw new RangeError('negative exponent');
  let x = base % modulus;
  if (x < 0n) x += modulus;
  let e = exponent;
  let result = 1n;
  while (e !== 0n) {
    if (e & 1n) result = (result * x) % modulus;
    x = (x * x) % modulus;
    e >>= 1n;
  }
  return result;
}

function invert(x, modulus = P) {
  let a = x % modulus;
  if (a < 0n) a += modulus;
  if (a === 0n) throw new RangeError('inverse of zero');

  // Extended Euclid is intentionally independent of the usual x^(p-2) path.
  let oldR = modulus;
  let r = a;
  let oldS = 0n;
  let s = 1n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) throw new RangeError('non-invertible value');
  const result = oldS % modulus;
  return result >= 0n ? result : result + modulus;
}

function asBytes(value, name = 'byte string') {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Buffer or Uint8Array`);
  }
  return Buffer.from(value);
}

function normalizeU64(value, name = 'integer') {
  let n;
  if (typeof value === 'bigint') {
    n = value;
  } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
    n = BigInt(value);
  } else {
    throw new RangeError(`${name} is not an exact integer`);
  }
  if (n < 0n || n > MAX_U64) throw new RangeError(`${name} is outside u64`);
  return n;
}

function u8(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new RangeError('outside u8');
  return Buffer.from([n]);
}

function u32be(n) {
  if (!Number.isInteger(n) || n < 0 || n > MAX_U32) throw new RangeError('outside u32');
  const out = Buffer.alloc(4);
  out.writeUInt32BE(n, 0);
  return out;
}

function u64be(value) {
  const n = normalizeU64(value, 'u64 value');
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(n, 0);
  return out;
}

function os2ipLE(bytes) {
  const b = asBytes(bytes);
  let result = 0n;
  for (let i = b.length - 1; i >= 0; --i) result = (result << 8n) + BigInt(b[i]);
  return result;
}

function i2ospLE(value, length) {
  if (typeof value !== 'bigint' || value < 0n || value >= (1n << BigInt(8 * length))) {
    throw new RangeError('integer does not fit output length');
  }
  const out = Buffer.alloc(length);
  let n = value;
  for (let i = 0; i < length; ++i) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function field(tag, value) {
  const bytes = asBytes(value, 'field value');
  return Buffer.concat([u8(tag), u64be(BigInt(bytes.length)), bytes]);
}

function shake256(input, outputLength = 64) {
  const bytes = asBytes(input, 'SHAKE input');
  if (!Number.isSafeInteger(outputLength) || outputLength < 0) {
    throw new RangeError('invalid SHAKE output length');
  }
  return crypto.createHash('shake256', { outputLength }).update(bytes).digest();
}

function h2s(frame) {
  return os2ipLE(shake256(frame, 64)) % Q;
}

function frameKeyScalar(seed, retry) {
  return Buffer.concat([
    DOM,
    u8(OP_KEY_SCALAR),
    u8(2),
    field(TAG_SEED, seed),
    field(TAG_RETRY, u32be(retry)),
  ]);
}

function framePrefix(seed) {
  return Buffer.concat([
    DOM,
    u8(OP_NONCE_PREFIX),
    u8(1),
    field(TAG_SEED, seed),
  ]);
}

function nonceBeforeMessage(prefix, publicKey, context, messageLength) {
  return Buffer.concat([
    DOM,
    u8(OP_NONCE),
    u8(5),
    field(TAG_PREFIX, prefix),
    field(TAG_PUBLIC_KEY, publicKey),
    field(TAG_CONTEXT, context),
    u8(TAG_MESSAGE),
    u64be(messageLength),
  ]);
}

function nonceAfterMessage(retry) {
  return field(TAG_RETRY, u32be(retry));
}

function challengeBeforeMessage(publicKey, context, messageLength) {
  return Buffer.concat([
    DOM,
    u8(OP_CHALLENGE),
    u8(4),
    field(TAG_PUBLIC_KEY, publicKey),
    field(TAG_CONTEXT, context),
    u8(TAG_MESSAGE),
    u64be(messageLength),
  ]);
}

function challengeAfterMessage(commitment) {
  return field(TAG_COMMITMENT_R, commitment);
}

function frameNonce(prefix, publicKey, context, message, retry) {
  return Buffer.concat([
    nonceBeforeMessage(prefix, publicKey, context, BigInt(message.length)),
    message,
    nonceAfterMessage(retry),
  ]);
}

function frameChallenge(publicKey, context, message, commitment) {
  return Buffer.concat([
    challengeBeforeMessage(publicKey, context, BigInt(message.length)),
    message,
    challengeAfterMessage(commitment),
  ]);
}

function point(X, Y, Z, T) {
  return { X: mod(X), Y: mod(Y), Z: mod(Z), T: mod(T) };
}

function affinePoint(x, y) {
  const xx = mod(x);
  const yy = mod(y);
  return point(xx, yy, 1n, xx * yy);
}

function identityPoint() {
  return point(0n, 1n, 1n, 0n);
}

/*
 * Complete extended-coordinate addition for
 *     a*x^2 + y^2 = 1 + d*x^2*y^2,
 * with T = X*Y/Z.  Completeness follows here from square a and nonsquare d.
 */
function addPoints(left, right) {
  const aa = mod(left.X * right.X);
  const bb = mod(left.Y * right.Y);
  const cc = mod(D_COEFF * left.T * right.T);
  const dd = mod(left.Z * right.Z);
  const ee = mod((left.X + left.Y) * (right.X + right.Y) - aa - bb);
  const ff = mod(dd - cc);
  const gg = mod(dd + cc);
  const hh = mod(bb - A_COEFF * aa);
  return point(ee * ff, gg * hh, ff * gg, ee * hh);
}

function negatePoint(p) {
  return point(-p.X, p.Y, p.Z, -p.T);
}

function scalarMultiply(p, scalar) {
  if (typeof scalar !== 'bigint') throw new TypeError('scalar must be BigInt');
  let n = scalar;
  let addend = p;
  if (n < 0n) {
    n = -n;
    addend = negatePoint(addend);
  }
  let result = identityPoint();
  while (n !== 0n) {
    if (n & 1n) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
    n >>= 1n;
  }
  return result;
}

function equalPoints(left, right) {
  return mod(left.X * right.Z - right.X * left.Z) === 0n &&
         mod(left.Y * right.Z - right.Y * left.Z) === 0n;
}

function isIdentity(p) {
  return mod(p.X) === 0n && mod(p.Y - p.Z) === 0n;
}

function toAffine(p) {
  if (mod(p.Z) === 0n) throw new Error('invalid projective point');
  const iz = invert(p.Z);
  return { x: mod(p.X * iz), y: mod(p.Y * iz) };
}

function isOnCurve(p) {
  let affine;
  try {
    affine = toAffine(p);
  } catch {
    return false;
  }
  const x2 = mod(affine.x * affine.x);
  const y2 = mod(affine.y * affine.y);
  return mod(A_COEFF * x2 + y2 - 1n - D_COEFF * x2 * y2) === 0n;
}

function encodePoint(p) {
  if (!isOnCurve(p)) throw new Error('cannot encode off-curve point');
  const { x, y } = toAffine(p);
  const out = i2ospLE(y, POINT_BYTES);
  // A canonical y is only 301 bits; bit 303 is free for parity(x).
  if ((out[37] & 0xe0) !== 0) throw new Error('field element exceeds point layout');
  if (x & 1n) out[37] |= 0x80;
  return out;
}

function decodePoint(encoded) {
  const input = asBytes(encoded, 'encoded point');
  if (input.length !== POINT_BYTES) throw new Error('wrong point length');
  if ((input[37] & 0x60) !== 0) throw new Error('reserved point bit set');

  const sign = (input[37] >>> 7) & 1;
  const yBytes = Buffer.from(input);
  yBytes[37] &= 0x1f;
  const y = os2ipLE(yBytes);
  if (y >= P) throw new Error('non-canonical y');

  const y2 = mod(y * y);
  const denominator = mod(A_COEFF - D_COEFF * y2);
  if (denominator === 0n) throw new Error('zero x-recovery denominator');
  const x2 = mod((1n - y2) * invert(denominator));
  let x = powMod(x2, (P + 1n) >> 2n);
  if (mod(x * x - x2) !== 0n) throw new Error('x is not in base field');
  if (x === 0n && sign !== 0) throw new Error('non-canonical sign for x=0');
  if (Number(x & 1n) !== sign) x = P - x;

  const result = affinePoint(x, y);
  if (!isOnCurve(result)) throw new Error('decoded point is off curve');
  return result;
}

function decodePrimeSubgroupPoint(encoded) {
  const p = decodePoint(encoded);
  if (isIdentity(p)) throw new Error('identity is forbidden');
  if (!isIdentity(scalarMultiply(p, Q))) throw new Error('point is outside prime subgroup');
  return p;
}

const BASEPOINT = decodePoint(BASEPOINT_ENCODING);
if (isIdentity(BASEPOINT) || !isIdentity(scalarMultiply(BASEPOINT, Q))) {
  throw new Error('normative basepoint failed subgroup validation');
}

function checkSeed(seed) {
  const bytes = asBytes(seed, 'seed');
  if (bytes.length !== 38) throw new Error('seed must be exactly 38 bytes');
  return bytes;
}

function checkContext(context) {
  const bytes = asBytes(context, 'context');
  if (bytes.length > 255) throw new Error('context exceeds 255 bytes');
  return bytes;
}

function deriveNonzero(frameFactory, reducer = h2s, startRetry = 0) {
  if (!Number.isInteger(startRetry) || startRetry < 0 || startRetry > MAX_U32) {
    throw new RangeError('invalid starting retry counter');
  }
  for (let retry = startRetry; retry <= MAX_U32; ++retry) {
    const scalar = reducer(frameFactory(retry), retry);
    if (typeof scalar !== 'bigint' || scalar < 0n || scalar >= Q) {
      throw new Error('scalar reducer returned value outside Z_q');
    }
    if (scalar !== 0n) return { scalar, retry };
    if (retry === MAX_U32) throw new Error('retry counter exhausted');
  }
  throw new Error('unreachable retry state');
}

function deriveKeyValues(seed, keyReducer = h2s) {
  const secretKey = checkSeed(seed);
  const keyResult = deriveNonzero((retry) => frameKeyScalar(secretKey, retry), keyReducer);
  const prefix = shake256(framePrefix(secretKey), 64);
  const publicPoint = scalarMultiply(BASEPOINT, keyResult.scalar);
  if (isIdentity(publicPoint) || !isIdentity(scalarMultiply(publicPoint, Q))) {
    throw new Error('internal public-key subgroup failure');
  }
  return {
    secretKey,
    scalar: keyResult.scalar,
    scalarRetry: keyResult.retry,
    prefix,
    publicPoint,
    publicKey: encodePoint(publicPoint),
  };
}

function keyGen(seed) {
  const values = deriveKeyValues(seed);
  return {
    secretKey: Buffer.from(values.secretKey),
    publicKey: Buffer.from(values.publicKey),
  };
}

function consumeChunks(chunks, expectedLength, states) {
  if (chunks === null || chunks === undefined || typeof chunks[Symbol.iterator] !== 'function') {
    throw new TypeError('message chunks must be iterable');
  }
  let seen = 0n;
  for (const value of chunks) {
    const chunk = asBytes(value, 'message chunk');
    seen += BigInt(chunk.length);
    if (seen > expectedLength) throw new Error('message longer than announced');
    for (const state of states) state.update(chunk);
  }
  if (seen !== expectedLength) throw new Error('message shorter than announced');
}

function signChunks(seed, context, messageLength, chunks) {
  const ctx = checkContext(context);
  const length = normalizeU64(messageLength, 'message_length');
  const key = deriveKeyValues(seed);

  const nonceState = crypto.createHash('shake256', { outputLength: 64 });
  nonceState.update(nonceBeforeMessage(key.prefix, key.publicKey, ctx, length));
  const challengeState = crypto.createHash('shake256', { outputLength: 64 });
  challengeState.update(challengeBeforeMessage(key.publicKey, ctx, length));
  consumeChunks(chunks, length, [nonceState, challengeState]);

  let nonce = 0n;
  for (let retry = 0; retry <= MAX_U32; ++retry) {
    const trial = nonceState.copy({ outputLength: 64 });
    trial.update(nonceAfterMessage(retry));
    nonce = os2ipLE(trial.digest()) % Q;
    if (nonce !== 0n) break;
    if (retry === MAX_U32) throw new Error('nonce-retry-exhausted');
  }

  const commitmentPoint = scalarMultiply(BASEPOINT, nonce);
  if (isIdentity(commitmentPoint) || !isIdentity(scalarMultiply(commitmentPoint, Q))) {
    throw new Error('internal commitment subgroup failure');
  }
  const commitment = encodePoint(commitmentPoint);
  challengeState.update(challengeAfterMessage(commitment));
  const challenge = os2ipLE(challengeState.digest()) % Q;
  const response = modQ(nonce + challenge * key.scalar);

  const left = scalarMultiply(BASEPOINT, response);
  const right = addPoints(commitmentPoint, scalarMultiply(key.publicPoint, challenge));
  if (!equalPoints(left, right)) throw new Error('internal signature equation failure');

  return Buffer.concat([commitment, i2ospLE(response, SCALAR_BYTES)]);
}

function sign(seed, context, messageLength, message) {
  const bytes = asBytes(message, 'message');
  return signChunks(seed, context, messageLength, [bytes]);
}

function prepareVerification(publicKey, context, messageLength, signature) {
  const publicBytes = asBytes(publicKey, 'public key');
  const ctx = checkContext(context);
  const length = normalizeU64(messageLength, 'message_length');
  const sig = asBytes(signature, 'signature');
  if (publicBytes.length !== POINT_BYTES || sig.length !== SIGNATURE_BYTES) {
    throw new Error('wrong outer encoding length');
  }
  const commitment = sig.subarray(0, POINT_BYTES);
  const responseBytes = sig.subarray(POINT_BYTES);
  const publicPoint = decodePrimeSubgroupPoint(publicBytes);
  const commitmentPoint = decodePrimeSubgroupPoint(commitment);
  const response = os2ipLE(responseBytes);
  if (response >= Q) throw new Error('non-canonical response scalar');
  return {
    publicBytes,
    ctx,
    length,
    commitment,
    response,
    publicPoint,
    commitmentPoint,
  };
}

function verifyChunks(publicKey, context, messageLength, chunks, signature) {
  try {
    const parsed = prepareVerification(publicKey, context, messageLength, signature);
    const challengeState = crypto.createHash('shake256', { outputLength: 64 });
    challengeState.update(challengeBeforeMessage(
      parsed.publicBytes,
      parsed.ctx,
      parsed.length,
    ));
    consumeChunks(chunks, parsed.length, [challengeState]);
    challengeState.update(challengeAfterMessage(parsed.commitment));
    const challenge = os2ipLE(challengeState.digest()) % Q;
    const left = scalarMultiply(BASEPOINT, parsed.response);
    const right = addPoints(
      parsed.commitmentPoint,
      scalarMultiply(parsed.publicPoint, challenge),
    );
    return equalPoints(left, right);
  } catch {
    return false;
  }
}

function verify(publicKey, context, messageLength, message, signature) {
  try {
    const bytes = asBytes(message, 'message');
    return verifyChunks(publicKey, context, messageLength, [bytes], signature);
  } catch {
    return false;
  }
}

function signInjected(seed, context, message, reducers = {}) {
  const ctx = checkContext(context);
  const msg = asBytes(message, 'message');
  const key = deriveKeyValues(seed, reducers.key || h2s);
  const nonceResult = deriveNonzero(
    (retry) => frameNonce(key.prefix, key.publicKey, ctx, msg, retry),
    reducers.nonce || h2s,
  );
  const commitmentPoint = scalarMultiply(BASEPOINT, nonceResult.scalar);
  const commitment = encodePoint(commitmentPoint);
  const challenge = (reducers.challenge || h2s)(
    frameChallenge(key.publicKey, ctx, msg, commitment),
    0,
  );
  if (typeof challenge !== 'bigint' || challenge < 0n || challenge >= Q) {
    throw new Error('challenge reducer returned value outside Z_q');
  }
  const response = modQ(nonceResult.scalar + challenge * key.scalar);
  const signature = Buffer.concat([commitment, i2ospLE(response, SCALAR_BYTES)]);
  return {
    signature,
    publicKey: key.publicKey,
    scalar: key.scalar,
    scalarRetry: key.scalarRetry,
    nonce: nonceResult.scalar,
    nonceRetry: nonceResult.retry,
    challenge,
    response,
  };
}

function verifyInjected(publicKey, context, message, signature, challengeReducer) {
  try {
    const ctx = checkContext(context);
    const msg = asBytes(message, 'message');
    const parsed = prepareVerification(publicKey, ctx, BigInt(msg.length), signature);
    const challenge = challengeReducer(
      frameChallenge(parsed.publicBytes, ctx, msg, parsed.commitment),
      0,
    );
    if (typeof challenge !== 'bigint' || challenge < 0n || challenge >= Q) return false;
    return equalPoints(
      scalarMultiply(BASEPOINT, parsed.response),
      addPoints(parsed.commitmentPoint, scalarMultiply(parsed.publicPoint, challenge)),
    );
  } catch {
    return false;
  }
}

function deriveBasepoint(counter = parameters.basepoint.first_counter) {
  const dst = Buffer.from(parameters.basepoint.derivation_dst_ascii, 'ascii');
  const raw = shake256(Buffer.concat([dst, u32be(counter)]), parameters.basepoint.xof_output_bytes);
  const candidate = Buffer.from(raw);
  candidate[37] &= 0x1f; // clear bits 301..303
  let p;
  try {
    p = decodePoint(candidate); // sign bit is now zero
  } catch {
    return { raw, point: null, encoded: null };
  }
  const cleared = scalarMultiply(p, BigInt(parameters.group.cofactor_h));
  if (isIdentity(cleared)) return { raw, point: null, encoded: null };
  return { raw, point: cleared, encoded: encodePoint(cleared) };
}

const exported = {
  keyGen,
  sign,
  signChunks,
  verify,
  verifyChunks,
  constants: Object.freeze({
    p: P,
    a: A_COEFF,
    d: D_COEFF,
    q: Q,
    fieldBytes: FIELD_BYTES,
    pointBytes: POINT_BYTES,
    scalarBytes: SCALAR_BYTES,
    signatureBytes: SIGNATURE_BYTES,
    dom: Buffer.from(DOM),
    basepointEncoding: Buffer.from(BASEPOINT_ENCODING),
  }),
};

// Test-only injection hooks are intentionally absent from the normal API.
if (process.env.ED301_ENABLE_TEST_HOOKS === '1') {
  exported.__testOnly = Object.freeze({
    mod,
    modQ,
    invert,
    powMod,
    os2ipLE,
    i2ospLE,
    u8,
    u32be,
    u64be,
    field,
    shake256,
    h2s,
    frameKeyScalar,
    framePrefix,
    frameNonce,
    frameChallenge,
    nonceBeforeMessage,
    nonceAfterMessage,
    challengeBeforeMessage,
    challengeAfterMessage,
    point: affinePoint,
    identityPoint,
    addPoints,
    negatePoint,
    scalarMultiply,
    equalPoints,
    isIdentity,
    isOnCurve,
    toAffine,
    encodePoint,
    decodePoint,
    decodePrimeSubgroupPoint,
    deriveKeyValues,
    deriveNonzero,
    signInjected,
    verifyInjected,
    deriveBasepoint,
    basepoint: BASEPOINT,
  });
}

module.exports = exported;
