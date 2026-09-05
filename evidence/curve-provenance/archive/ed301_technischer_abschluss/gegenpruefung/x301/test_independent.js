'use strict';

/* Pre-vector independent tests for the NOT-FOR-PRODUCTION X301-v1 audit code. */

process.env.X301_ENABLE_TEST_HOOKS = '1';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const x301 = require('./x301.js');
const t = x301.__testOnly;
const C = x301.constants;
const parameterPath = path.join(__dirname, '..', '..', 'parameter', 'ed301-v1.json');
const parameters = JSON.parse(fs.readFileSync(parameterPath, 'utf8'));

let passed = 0;
const failures = [];

function test(name, body) {
  try {
    body();
    ++passed;
    process.stdout.write(`ok ${passed} - ${name}\n`);
  } catch (error) {
    failures.push({ name, error });
    process.stdout.write(`not ok - ${name}\n${error.stack}\n`);
  }
}

function expectCode(body, code) {
  assert.throws(body, (error) => error instanceof x301.X301Error && error.code === code);
}

function fromHex(hex) {
  return Buffer.from(hex, 'hex');
}

function localMod(value) {
  const reduced = value % C.p;
  return reduced >= 0n ? reduced : reduced + C.p;
}

// Deliberately different inversion path from x301.js: Fermat exponentiation.
function localPow(base, exponent) {
  let x = localMod(base);
  let e = exponent;
  let result = 1n;
  while (e !== 0n) {
    if (e & 1n) result = localMod(result * x);
    x = localMod(x * x);
    e >>= 1n;
  }
  return result;
}

function localInvert(value) {
  const x = localMod(value);
  if (x === 0n) throw new Error('local inverse of zero');
  return localPow(x, C.p - 2n);
}

function localSqrt(value) {
  const square = localMod(value);
  const root = localPow(square, (C.p + 1n) >> 2n);
  return localMod(root * root) === square ? root : null;
}

function wOnCurve(point, a2, a4) {
  if (point === null) return true;
  return localMod(point.y * point.y - point.x * point.x * point.x - a2 * point.x * point.x - a4 * point.x) === 0n;
}

function wAdd(left, right, a2, a4) {
  if (left === null) return right;
  if (right === null) return left;
  let slope;
  if (left.x === right.x) {
    if (localMod(left.y + right.y) === 0n) return null;
    slope = localMod(
      (3n * left.x * left.x + 2n * a2 * left.x + a4) * localInvert(2n * left.y),
    );
  } else {
    slope = localMod((right.y - left.y) * localInvert(right.x - left.x));
  }
  const x = localMod(slope * slope - a2 - left.x - right.x);
  const y = localMod(-left.y + slope * (left.x - x));
  const result = { x, y };
  assert.ok(wOnCurve(result, a2, a4));
  return result;
}

function wMultiply(point, scalar, a2, a4) {
  let n = scalar;
  let result = null;
  let addend = point;
  while (n !== 0n) {
    if (n & 1n) result = wAdd(result, addend, a2, a4);
    addend = wAdd(addend, addend, a2, a4);
    n >>= 1n;
  }
  return result;
}

const B = BigInt(parameters.montgomery.B_decimal);
const W_A2 = BigInt(parameters.weierstrass.coefficients[1]);
const W_A4 = BigInt(parameters.weierstrass.coefficients[3]);
const TWIST_A2 = BigInt(parameters.twist.weierstrass_coefficients[1]);
const TWIST_A4 = BigInt(parameters.twist.weierstrass_coefficients[3]);
const TWIST_Z = BigInt(parameters.twist.non_square_z);

function mainPointFromU(u) {
  const X = localMod(B * u);
  const rhs = localMod(X * X * X + W_A2 * X * X + W_A4 * X);
  const Y = localSqrt(rhs);
  return Y === null ? null : { x: X, y: Y };
}

function twistPointFromU(u) {
  const X = localMod(TWIST_Z * B * u);
  const rhs = localMod(X * X * X + TWIST_A2 * X * X + TWIST_A4 * X);
  const Y = localSqrt(rhs);
  return Y === null ? null : { x: X, y: Y };
}

function findRegularU(kind) {
  for (let u = 2n; u < 1000n; ++u) {
    const point = kind === 'main' ? mainPointFromU(u) : twistPointFromU(u);
    if (point !== null) return { u, point };
  }
  throw new Error(`no small ${kind} u found`);
}

function affineCrossOutput(point, scalar, kind) {
  const a2 = kind === 'main' ? W_A2 : TWIST_A2;
  const a4 = kind === 'main' ? W_A4 : TWIST_A4;
  const multiplied = wMultiply(point, scalar, a2, a4);
  if (multiplied === null) return null;
  const scale = kind === 'main' ? B : localMod(TWIST_Z * B);
  return localMod(multiplied.x * localInvert(scale));
}

const SECRET_A = fromHex(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425',
);
const CLAMPED_A = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232415';
const K_A = 2691581607853636448229120878161405032208859867979755120621400250181915984534657846344810752n;
const PUBLIC_A = fromHex('b5d19e31e6bfa6f5c47411738360ba94b7bbff1c4bb9fc646e9775bbd7565a6052819781c21a');

const SECRET_B = fromHex(
  '2524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100',
);
const CLAMPED_B = '2424232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020110';
const K_B = 2037537207793484191264682445518406227957686363589790998502502283221196680013951291147625508n;
const PUBLIC_B = fromHex('86a7fa2ccb11a76c34fd7bca0f6e592c9991cb554cd7b326a2177df7dbb0f4c514381519921d');
const SHARED_AB = fromHex('70a54bebecf4a6f68aa30e6b081d29fb59da71ebd6fbf34f14780650ea2baa076c3afc7a4111');
const NT_SECRET = fromHex('5caf05bd7871f4673bd712e08efdb5dddf8ca4ffffffffffffffffffffffffffffffffffff1f');

test('field, order, and A24 constants reproduce their formulas', () => {
  assert.equal(C.p, (1n << 301n) - (1n << 99n) + 947n);
  assert.equal(C.order, 4n * C.q);
  assert.equal(C.twistOrder, 4n * C.qTwist);
  assert.equal(C.a24Minus, localMod((C.A - 2n) * localInvert(4n)));
  assert.equal(C.ladderBits, 301);
  assert.equal(C.fieldBytes, 38);
});

test('base u encoding is canonical little-endian', () => {
  assert.equal(t.decodeU(C.baseUEncoded), C.baseU);
  assert.deepEqual(t.encodeU(C.baseU), C.baseUEncoded);
});

test('normative secret A clamps to the fixed bytes and integer', () => {
  const decoded = t.decodeScalarDetailed(SECRET_A);
  assert.equal(decoded.clamped.toString('hex'), CLAMPED_A);
  assert.equal(decoded.scalar, K_A);
});

test('normative secret B clamps to the fixed bytes and integer', () => {
  const decoded = t.decodeScalarDetailed(SECRET_B);
  assert.equal(decoded.clamped.toString('hex'), CLAMPED_B);
  assert.equal(decoded.scalar, K_B);
});

test('all-zero and all-one raw secrets reach exact clamp boundaries', () => {
  assert.equal(t.decodeScalar(Buffer.alloc(38)), 1n << 300n);
  assert.equal(t.decodeScalar(Buffer.alloc(38, 0xff)), (1n << 301n) - 4n);
});

test('clamped scalar set has exactly 2^298 values before Nt exclusion', () => {
  const minimum = 1n << 300n;
  const maximum = (1n << 301n) - 4n;
  assert.equal((maximum - minimum) / 4n + 1n, 1n << 298n);
});

test('all six overwritten raw bits leave the clamped result unchanged', () => {
  const positions = [0, 1, 300, 301, 302, 303];
  const base = Buffer.from(SECRET_A);
  for (const position of positions) base[Math.floor(position / 8)] &= ~(1 << (position % 8));
  const expected = t.clampBytes(base);
  for (let combination = 0; combination < 64; ++combination) {
    const candidate = Buffer.from(base);
    for (let i = 0; i < positions.length; ++i) {
      if ((combination >> i) & 1) {
        const position = positions[i];
        candidate[Math.floor(position / 8)] |= 1 << (position % 8);
      }
    }
    assert.deepEqual(t.clampBytes(candidate), expected);
  }
});

test('every one of the 64 raw preimages of Nt is rejected', () => {
  const positions = [0, 1, 300, 301, 302, 303];
  const base = Buffer.from(NT_SECRET);
  for (const position of positions) base[Math.floor(position / 8)] &= ~(1 << (position % 8));
  for (let combination = 0; combination < 64; ++combination) {
    const candidate = Buffer.from(base);
    for (let i = 0; i < positions.length; ++i) {
      if ((combination >> i) & 1) {
        const position = positions[i];
        candidate[Math.floor(position / 8)] |= 1 << (position % 8);
      }
    }
    expectCode(() => t.decodeScalar(candidate), 'secret-nt');
  }
});

test('secret decoding rejects types and lengths without normalization', () => {
  expectCode(() => t.decodeScalar('00'.repeat(38)), 'secret-type');
  expectCode(() => t.decodeScalar(Buffer.alloc(37)), 'secret-length');
  expectCode(() => t.decodeScalar(Buffer.alloc(39)), 'secret-length');
});

test('u codec round-trips zero, p-1, and the fixed base', () => {
  for (const value of [0n, C.p - 1n, C.baseU]) {
    assert.equal(t.decodeU(t.encodeU(value)), value);
  }
});

test('u decoder rejects types and wrong lengths', () => {
  expectCode(() => t.decodeU('00'.repeat(38)), 'u-type');
  expectCode(() => t.decodeU(Buffer.alloc(37)), 'u-length');
  expectCode(() => t.decodeU(Buffer.alloc(39)), 'u-length');
});

test('each reserved u bit is rejected rather than masked', () => {
  for (const mask of [0x20, 0x40, 0x80]) {
    const encoded = Buffer.from(C.baseUEncoded);
    encoded[37] |= mask;
    expectCode(() => t.decodeU(encoded), 'u-reserved-bits');
  }
});

test('u=p and larger 301-bit u values are rejected rather than reduced', () => {
  expectCode(() => t.decodeU(t.i2ospLE38(C.p)), 'u-noncanonical');
  expectCode(() => t.decodeU(t.i2ospLE38(C.p + 1n)), 'u-noncanonical');
  expectCode(() => t.decodeU(t.i2ospLE38((1n << 301n) - 1n)), 'u-noncanonical');
});

test('u encoder rejects nonintegers and values outside F_p', () => {
  expectCode(() => t.encodeU(-1n), 'u-encode-range');
  expectCode(() => t.encodeU(C.p), 'u-encode-range');
  expectCode(() => t.encodeU(1), 'u-encode-range');
});

test('ladder executes exactly 301 rounds at both scalar boundaries', () => {
  for (const scalar of [1n << 300n, (1n << 301n) - 4n]) {
    assert.equal(t.ladder301(scalar, C.baseU).iterations, 301);
  }
});

test('ladder validates scalar range, divisibility, Nt, and field u', () => {
  expectCode(() => t.ladder301((1n << 300n) - 4n, C.baseU), 'ladder-scalar-range');
  expectCode(() => t.ladder301((1n << 300n) + 1n, C.baseU), 'ladder-scalar-divisibility');
  expectCode(() => t.ladder301(C.twistOrder, C.baseU), 'secret-nt');
  expectCode(() => t.ladder301(1n << 300n, C.p), 'ladder-u-range');
});

test('normative Public values for A and B match exactly', () => {
  assert.deepEqual(x301.publicKey(SECRET_A), PUBLIC_A);
  assert.deepEqual(x301.publicKey(SECRET_B), PUBLIC_B);
});

test('normative Shared result is symmetric and exact', () => {
  assert.deepEqual(x301.shared(SECRET_A, PUBLIC_B), SHARED_AB);
  assert.deepEqual(x301.shared(SECRET_B, PUBLIC_A), SHARED_AB);
});

test('normal aliases invoke the same core operations', () => {
  assert.deepEqual(x301.X301(SECRET_A, C.baseUEncoded), PUBLIC_A);
  assert.deepEqual(x301.Public(SECRET_A), PUBLIC_A);
  assert.deepEqual(x301.Shared(SECRET_A, PUBLIC_B), SHARED_AB);
});

test('ignored raw-secret bits produce identical public and shared outputs', () => {
  const changed = Buffer.from(SECRET_A);
  changed[0] ^= 0x03;
  changed[37] ^= 0xf0;
  assert.deepEqual(t.clampBytes(changed), t.clampBytes(SECRET_A));
  assert.deepEqual(x301.publicKey(changed), PUBLIC_A);
  assert.deepEqual(x301.shared(changed, PUBLIC_B), SHARED_AB);
});

test('Nt secret is rejected by core, Public, and Shared', () => {
  expectCode(() => x301.x301(NT_SECRET, C.baseUEncoded), 'secret-nt');
  expectCode(() => x301.publicKey(NT_SECRET), 'secret-nt');
  expectCode(() => x301.shared(NT_SECRET, PUBLIC_A), 'secret-nt');
});

test('u=0 and u=1 cofactor torsion produce mandatory infinity failure', () => {
  expectCode(() => x301.shared(SECRET_A, t.encodeU(0n)), 'ladder-infinity');
  expectCode(() => x301.shared(SECRET_A, t.encodeU(1n)), 'ladder-infinity');
});

test('projective finalization separately rejects Z=0 and all-zero output', () => {
  expectCode(() => t.finalizeProjective(1n, 0n), 'ladder-infinity');
  expectCode(() => t.finalizeProjective(0n, 1n), 'all-zero-output');
});

test('successful outputs are canonical and nonzero', () => {
  for (const output of [PUBLIC_A, PUBLIC_B, SHARED_AB]) {
    assert.equal(output.length, 38);
    assert.equal(output[37] & 0xe0, 0);
    assert.ok(t.decodeU(output) < C.p);
    assert.equal(t.allZero(output), false);
  }
});

test('Public rejects imported secrets with wrong form', () => {
  expectCode(() => x301.publicKey(Buffer.alloc(37)), 'secret-length');
  expectCode(() => x301.publicKey(Buffer.alloc(39)), 'secret-length');
  expectCode(() => x301.publicKey(null), 'secret-type');
});

test('Shared applies strict peer-u parsing before the ladder', () => {
  expectCode(() => x301.shared(SECRET_A, Buffer.alloc(37)), 'u-length');
  expectCode(() => x301.shared(SECRET_A, t.i2ospLE38(C.p)), 'u-noncanonical');
  const high = Buffer.from(C.baseUEncoded);
  high[37] |= 0x20;
  expectCode(() => x301.shared(SECRET_A, high), 'u-reserved-bits');
});

test('KeyGen retries only Nt and returns the original next raw secret', () => {
  let calls = 0;
  const result = x301.keyGen((length) => {
    assert.equal(length, 38);
    ++calls;
    return calls === 1 ? NT_SECRET : SECRET_A;
  });
  assert.equal(calls, 2);
  assert.deepEqual(result.secretKey, SECRET_A);
  assert.deepEqual(result.publicKey, PUBLIC_A);
});

test('KeyGen fails on RNG type, failure, and wrong output length', () => {
  expectCode(() => x301.keyGen(7), 'rng-type');
  expectCode(() => x301.keyGen(() => { throw new Error('offline'); }), 'rng-failure');
  expectCode(() => x301.keyGen(() => Buffer.alloc(37)), 'rng-length');
  expectCode(() => x301.keyGen(() => '00'.repeat(38)), 'rng-type');
});

test('main-curve base multiplication agrees with separate affine Weierstrass arithmetic', () => {
  const basePoint = {
    x: localMod(B * C.baseU),
    y: localMod(B * B * BigInt(parameters.basepoint.G_montgomery_v_decimal)),
  };
  assert.ok(wOnCurve(basePoint, W_A2, W_A4));
  const expectedU = affineCrossOutput(basePoint, K_A, 'main');
  assert.notEqual(expectedU, null);
  assert.equal(expectedU, t.decodeU(PUBLIC_A));
});

test('regular main-curve input agrees with separate affine Weierstrass arithmetic', () => {
  const found = findRegularU('main');
  assert.ok(wOnCurve(found.point, W_A2, W_A4));
  const expectedU = affineCrossOutput(found.point, K_B, 'main');
  assert.notEqual(expectedU, null);
  const actual = x301.x301(SECRET_B, t.encodeU(found.u));
  assert.equal(t.decodeU(actual), expectedU);
});

test('regular twist input agrees with separate affine twist arithmetic', () => {
  const found = findRegularU('twist');
  assert.ok(wOnCurve(found.point, TWIST_A2, TWIST_A4));
  const expectedU = affineCrossOutput(found.point, K_A, 'twist');
  assert.notEqual(expectedU, null);
  const actual = x301.x301(SECRET_A, t.encodeU(found.u));
  assert.equal(t.decodeU(actual), expectedU);
});

test('test-only hooks are absent from the normal module API', () => {
  const script = [
    "delete process.env.X301_ENABLE_TEST_HOOKS;",
    "const x=require('./ed301_technischer_abschluss/gegenpruefung/x301/x301.js');",
    "process.exit(x.__testOnly === undefined ? 0 : 1);",
  ].join('');
  const result = childProcess.spawnSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..', '..', '..'),
  });
  assert.equal(result.status, 0, result.stderr.toString());
});

process.stdout.write(`# ${passed} passed, ${failures.length} failed\n`);
if (failures.length !== 0) process.exitCode = 1;

