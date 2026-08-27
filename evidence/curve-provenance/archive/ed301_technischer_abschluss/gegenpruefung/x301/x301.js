'use strict';

/*
 * Independent X301-v1 Node.js BigInt counter-implementation.
 *
 * NOT FOR PRODUCTION: JavaScript BigInt operations, branches, swaps, inversion,
 * and error handling in this audit implementation are not constant-time.
 *
 * Independence rule: written only from parameter/ed301-v1.json,
 * spezifikation/ED301-v1.md, and spezifikation/X301-v1.md.  No Python
 * reference, test, or vector generator is imported or used.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PARAMETER_PATH = path.join(__dirname, '..', '..', 'parameter', 'ed301-v1.json');
const parameters = JSON.parse(fs.readFileSync(PARAMETER_PATH, 'utf8'));

const P = BigInt(parameters.field.p_decimal);
const A = BigInt(parameters.montgomery.A_decimal);
const A24_MINUS = BigInt(parameters.montgomery.A24_minus_decimal);
const N = BigInt(parameters.group.order_N_decimal);
const Q = BigInt(parameters.group.q_decimal);
const N_TWIST = BigInt(parameters.twist.order_decimal);
const Q_TWIST = BigInt(parameters.twist.q_twist_decimal);
const FIELD_BYTES = parameters.encoding.field_bytes;
const LADDER_BITS = parameters.field.bit_length;
const BASE_U = BigInt(parameters.basepoint.G_montgomery_u_decimal);
const BASE_U_ENCODED = Buffer.from(parameters.basepoint.G_montgomery_u_little_endian_hex, 'hex');

class X301Error extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'X301Error';
    this.code = code;
  }
}

function fail(code, message) {
  throw new X301Error(code, message);
}

function mod(value) {
  const reduced = value % P;
  return reduced >= 0n ? reduced : reduced + P;
}

function invert(value) {
  let r0 = P;
  let r1 = mod(value);
  if (r1 === 0n) fail('field-inverse-zero', 'cannot invert zero');
  let s0 = 0n;
  let s1 = 1n;
  while (r1 !== 0n) {
    const quotient = r0 / r1;
    [r0, r1] = [r1, r0 - quotient * r1];
    [s0, s1] = [s1, s0 - quotient * s1];
  }
  if (r0 !== 1n) fail('field-noninvertible', 'field value is not invertible');
  return mod(s0);
}

function isByteString(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function copyBytes(value, code, name) {
  if (!isByteString(value)) fail(code, `${name} is not a byte string`);
  return Buffer.from(value);
}

function os2ipLE(value) {
  const bytes = copyBytes(value, 'integer-type', 'integer input');
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; --i) result = (result << 8n) + BigInt(bytes[i]);
  return result;
}

function i2ospLE38(value) {
  if (typeof value !== 'bigint' || value < 0n || value >= (1n << 304n)) {
    fail('integer-range', 'integer does not fit 38 bytes');
  }
  const output = Buffer.alloc(FIELD_BYTES);
  let remaining = value;
  for (let i = 0; i < FIELD_BYTES; ++i) {
    output[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function encodeU(value) {
  if (typeof value !== 'bigint' || value < 0n || value >= P) {
    fail('u-encode-range', 'u is outside the canonical field range');
  }
  const output = i2ospLE38(value);
  if ((output[37] & 0xe0) !== 0) fail('internal-u-high-bits', 'encoded u has reserved bits');
  return output;
}

function decodeU(encoded) {
  const input = copyBytes(encoded, 'u-type', 'u input');
  if (input.length !== FIELD_BYTES) fail('u-length', 'u input must be exactly 38 bytes');
  if ((input[37] & 0xe0) !== 0) fail('u-reserved-bits', 'u input has a reserved high bit');
  const value = os2ipLE(input);
  if (value >= P) fail('u-noncanonical', 'u input is not canonical');
  return value;
}

function clampBytes(secret) {
  const input = copyBytes(secret, 'secret-type', 'secret');
  if (input.length !== FIELD_BYTES) fail('secret-length', 'secret must be exactly 38 bytes');
  const clamped = Buffer.from(input);
  clamped[0] &= 0xfc;
  clamped[37] = (clamped[37] & 0x0f) | 0x10;
  return clamped;
}

function decodeScalarDetailed(secret) {
  const clamped = clampBytes(secret);
  const scalar = os2ipLE(clamped);
  if (scalar === N_TWIST) fail('secret-nt', 'clamped scalar equals the twist order');
  return { scalar, clamped };
}

function decodeScalar(secret) {
  return decodeScalarDetailed(secret).scalar;
}

function validateLadderInputs(scalar, u) {
  if (typeof scalar !== 'bigint' || scalar < (1n << 300n) || scalar > (1n << 301n) - 4n) {
    fail('ladder-scalar-range', 'scalar is outside the clamped interval');
  }
  if ((scalar & 3n) !== 0n) fail('ladder-scalar-divisibility', 'scalar is not divisible by four');
  if (scalar === N_TWIST) fail('secret-nt', 'clamped scalar equals the twist order');
  if (typeof u !== 'bigint' || u < 0n || u >= P) fail('ladder-u-range', 'u is outside F_p');
}

function ladder301(scalar, u) {
  validateLadderInputs(scalar, u);

  const x1 = u;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = u;
  let z3 = 1n;
  let swap = 0;
  let iterations = 0;

  for (let bitIndex = LADDER_BITS - 1; bitIndex >= 0; --bitIndex) {
    const bit = Number((scalar >> BigInt(bitIndex)) & 1n);
    swap ^= bit;
    if (swap !== 0) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = bit;

    const aSum = mod(x2 + z2);
    const aa = mod(aSum * aSum);
    const bDifference = mod(x2 - z2);
    const bb = mod(bDifference * bDifference);
    const e = mod(aa - bb);
    const cSum = mod(x3 + z3);
    const dDifference = mod(x3 - z3);
    const da = mod(dDifference * aSum);
    const cb = mod(cSum * bDifference);

    x3 = mod((da + cb) * (da + cb));
    z3 = mod(x1 * mod((da - cb) * (da - cb)));
    x2 = mod(aa * bb);
    z2 = mod(e * mod(aa + A24_MINUS * e));
    ++iterations;
  }

  if (swap !== 0) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }
  return { X: x2, Z: z2, iterations };
}

function allZero(value) {
  const bytes = copyBytes(value, 'allzero-type', 'AllZero input');
  let accumulator = 0;
  for (const byte of bytes) accumulator |= byte;
  return accumulator === 0;
}

function finalizeProjective(X, Z) {
  if (typeof X !== 'bigint' || typeof Z !== 'bigint') {
    fail('projective-type', 'projective coordinates must be integers');
  }
  const zz = mod(Z);
  if (zz === 0n) fail('ladder-infinity', 'ladder result is the point at infinity');
  const affine = mod(mod(X) * invert(zz));
  const output = encodeU(affine);
  if (allZero(output)) fail('all-zero-output', 'X301 output is all zero');
  return output;
}

function x301(secret, encodedU) {
  const scalar = decodeScalar(secret);
  const u = decodeU(encodedU);
  const result = ladder301(scalar, u);
  return finalizeProjective(result.X, result.Z);
}

function publicKey(secret) {
  return x301(secret, BASE_U_ENCODED);
}

function shared(secret, peerPublic) {
  return x301(secret, peerPublic);
}

function keyGen(randomSource = crypto.randomBytes) {
  if (typeof randomSource !== 'function') fail('rng-type', 'random source must be callable');
  for (;;) {
    let generated;
    try {
      generated = randomSource(FIELD_BYTES);
    } catch (error) {
      fail('rng-failure', `random source failed: ${error.message}`);
    }
    const secret = copyBytes(generated, 'rng-type', 'random source output');
    if (secret.length !== FIELD_BYTES) fail('rng-length', 'random source returned the wrong length');
    try {
      decodeScalar(secret);
    } catch (error) {
      if (error instanceof X301Error && error.code === 'secret-nt') continue;
      throw error;
    }
    const publicBytes = publicKey(secret);
    return { secretKey: Buffer.from(secret), publicKey: publicBytes };
  }
}

const exported = {
  X301Error,
  x301,
  X301: x301,
  publicKey,
  Public: publicKey,
  shared,
  Shared: shared,
  keyGen,
  KeyGen: keyGen,
  constants: Object.freeze({
    p: P,
    A,
    a24Minus: A24_MINUS,
    order: N,
    q: Q,
    twistOrder: N_TWIST,
    qTwist: Q_TWIST,
    fieldBytes: FIELD_BYTES,
    ladderBits: LADDER_BITS,
    baseU: BASE_U,
    baseUEncoded: Buffer.from(BASE_U_ENCODED),
  }),
};

// Test hooks never appear in the default API.
if (process.env.X301_ENABLE_TEST_HOOKS === '1') {
  exported.__testOnly = Object.freeze({
    mod,
    invert,
    os2ipLE,
    i2ospLE38,
    encodeU,
    decodeU,
    clampBytes,
    decodeScalarDetailed,
    decodeScalar,
    validateLadderInputs,
    ladder301,
    allZero,
    finalizeProjective,
  });
}

module.exports = exported;

