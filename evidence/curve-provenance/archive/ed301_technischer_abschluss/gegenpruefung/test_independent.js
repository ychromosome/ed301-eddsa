'use strict';

/* Independent tests for the NOT-FOR-PRODUCTION Node.js implementation. */

process.env.ED301_ENABLE_TEST_HOOKS = '1';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ed = require('./ed301.js');
const t = ed.__testOnly;
const C = ed.constants;
const parameterPath = path.join(__dirname, '..', 'parameter', 'ed301-v1.json');
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

function throws(body, pattern) {
  assert.throws(body, pattern);
}

function pointEncodingForY(y, sign = 0) {
  const out = t.i2ospLE(y, C.pointBytes);
  if (sign) out[37] |= 0x80;
  return out;
}

const zeroSeed = Buffer.alloc(38);
const sequenceSeed = Buffer.from(Array.from({ length: 38 }, (_, i) => i));
const empty = Buffer.alloc(0);
const shortContext = Buffer.from('ED301 test context', 'utf8');
const shortMessage = Buffer.from('independent Node.js implementation', 'utf8');

test('field formula and symbolic a derivation', () => {
  assert.equal(C.p, (1n << 301n) - (1n << 99n) + 947n);
  assert.equal(C.a, 45677n ** 2n);
  assert.equal(C.d, 301n);
  assert.equal(C.q * 4n, BigInt(parameters.group.order_N_decimal));
});

test('normative domain bytes', () => {
  assert.equal(C.dom.toString('hex'), '0c45643330312d5369672d76310100');
  assert.equal(C.dom.length, 15);
});

test('SHAKE256 empty-input 64-byte FIPS 202 known answer', () => {
  assert.equal(
    t.shake256(Buffer.alloc(0), 64).toString('hex'),
    '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
      'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be',
  );
});

test('integer encoders use their normative byte orders', () => {
  assert.equal(t.u32be(0x01020304).toString('hex'), '01020304');
  assert.equal(t.u64be(0x0102030405060708n).toString('hex'), '0102030405060708');
  assert.equal(t.i2ospLE(0x01020304n, 8).toString('hex'), '0403020100000000');
  assert.equal(t.os2ipLE(Buffer.from('0403020100000000', 'hex')), 0x01020304n);
});

test('integer encoders reject overflow instead of truncating', () => {
  throws(() => t.u8(256), /u8/);
  throws(() => t.u32be(0x100000000), /u32/);
  throws(() => t.u64be(1n << 64n), /u64/);
  throws(() => t.u64be(Number.MAX_SAFE_INTEGER + 1), /exact integer/);
  throws(() => t.i2ospLE(1n << 304n, 38), /fit/);
});

test('key-scalar frame has exact tags, counts, lengths, and counter zero', () => {
  const expected =
    '0c45643330312d5369672d76310100' +
    '0102' +
    '010000000000000026' + '00'.repeat(38) +
    '02000000000000000400000000';
  assert.equal(t.frameKeyScalar(zeroSeed, 0).toString('hex'), expected);
});

test('nonce-prefix frame has exact operation and one seed field', () => {
  const expected =
    '0c45643330312d5369672d76310100' +
    '0201' +
    '010000000000000026' + '00'.repeat(38);
  assert.equal(t.framePrefix(zeroSeed).toString('hex'), expected);
});

test('synthetic u64 maximum is encoded without message allocation', () => {
  const prefix = t.challengeBeforeMessage(C.basepointEncoding, empty, (1n << 64n) - 1n);
  assert.equal(prefix.subarray(-9).toString('hex'), '06ffffffffffffffff');
});

test('basepoint counter-zero XOF is exactly the published value', () => {
  const derived = t.deriveBasepoint(0);
  assert.equal(derived.raw.toString('hex'), parameters.basepoint.xof_output_hex);
});

test('basepoint derivation independently reaches the published encoding', () => {
  const derived = t.deriveBasepoint(0);
  assert.ok(derived.point);
  assert.equal(derived.encoded.toString('hex'), parameters.basepoint.G_compressed_edwards_hex);
});

test('published basepoint decodes, re-encodes, and lies on curve', () => {
  const G = t.decodePoint(C.basepointEncoding);
  assert.ok(t.isOnCurve(G));
  assert.equal(t.encodePoint(G).toString('hex'), C.basepointEncoding.toString('hex'));
});

test('published basepoint has order q', () => {
  assert.ok(!t.isIdentity(t.basepoint));
  assert.ok(t.isIdentity(t.scalarMultiply(t.basepoint, C.q)));
});

test('scalar multiplication handles zero, one, q+1, and negatives', () => {
  assert.ok(t.isIdentity(t.scalarMultiply(t.basepoint, 0n)));
  assert.ok(t.equalPoints(t.scalarMultiply(t.basepoint, 1n), t.basepoint));
  assert.ok(t.equalPoints(t.scalarMultiply(t.basepoint, C.q + 1n), t.basepoint));
  assert.ok(t.isIdentity(t.addPoints(
    t.scalarMultiply(t.basepoint, -17n),
    t.scalarMultiply(t.basepoint, 17n),
  )));
});

test('complete addition is associative on fixed independent multiples', () => {
  const p3 = t.scalarMultiply(t.basepoint, 3n);
  const p5 = t.scalarMultiply(t.basepoint, 5n);
  const p7 = t.scalarMultiply(t.basepoint, 7n);
  assert.ok(t.equalPoints(
    t.addPoints(t.addPoints(p3, p5), p7),
    t.addPoints(p3, t.addPoints(p5, p7)),
  ));
  assert.ok(t.equalPoints(t.addPoints(p3, p5), t.scalarMultiply(t.basepoint, 8n)));
});

test('identity encoding decodes but strict subgroup public-key decoding rejects it', () => {
  const encoded = pointEncodingForY(1n);
  assert.ok(t.isIdentity(t.decodePoint(encoded)));
  throws(() => t.decodePrimeSubgroupPoint(encoded), /identity/);
});

test('order-two point decodes and strict subgroup decoding rejects it', () => {
  const encoded = pointEncodingForY(C.p - 1n);
  const p2 = t.decodePoint(encoded);
  assert.ok(!t.isIdentity(p2));
  assert.ok(t.isIdentity(t.addPoints(p2, p2)));
  throws(() => t.decodePrimeSubgroupPoint(encoded), /outside prime subgroup/);
});

test('published order-four point has exact order four', () => {
  const x = BigInt(parameters.edwards.order_4_point.x);
  const p4 = t.point(x, 0n);
  assert.ok(t.isOnCurve(p4));
  assert.ok(!t.isIdentity(t.scalarMultiply(p4, 2n)));
  assert.ok(t.isIdentity(t.scalarMultiply(p4, 4n)));
});

test('mixed-order point is rejected by strict subgroup validation', () => {
  const p2 = t.decodePoint(pointEncodingForY(C.p - 1n));
  const mixed = t.addPoints(t.basepoint, p2);
  const encoded = t.encodePoint(mixed);
  throws(() => t.decodePrimeSubgroupPoint(encoded), /outside prime subgroup/);
});

test('reserved point bits are rejected independently', () => {
  for (const mask of [0x20, 0x40]) {
    const malformed = Buffer.from(C.basepointEncoding);
    malformed[37] |= mask;
    throws(() => t.decodePoint(malformed), /reserved/);
  }
});

test('y equal to p is not silently reduced', () => {
  throws(() => t.decodePoint(pointEncodingForY(C.p)), /non-canonical y/);
});

test('x=0 with sign bit one is non-canonical', () => {
  throws(() => t.decodePoint(pointEncodingForY(1n, 1)), /non-canonical sign/);
  throws(() => t.decodePoint(pointEncodingForY(C.p - 1n, 1)), /non-canonical sign/);
});

test('at least one deterministic small-y non-point is rejected', () => {
  let rejected = false;
  for (let y = 2n; y < 100n; ++y) {
    try {
      t.decodePoint(pointEncodingForY(y));
    } catch {
      rejected = true;
      break;
    }
  }
  assert.ok(rejected);
});

test('zero-seed bootstrap KAT is stable', () => {
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  assert.equal(
    keys.publicKey.toString('hex'),
    'f2bb6bf1d5860859263b32b13d8f09fa9ce512a0abb03950109c84f8dabed6c3c7c960e6a602',
  );
  assert.equal(
    signature.toString('hex'),
    'dc40b096d9c0b3d72f2b54871a39ca68001031c2e344ef0f8ca5531acca3ca42a045ff59d911' +
      '368656ce7fb120d41d6abdec2f9b76f5046396828036e84e31c058aa7bee0d10b66f8b3e9a03',
  );
});

test('second deterministic bootstrap KAT is stable', () => {
  const keys = ed.keyGen(sequenceSeed);
  const signature = ed.sign(sequenceSeed, shortContext, BigInt(shortMessage.length), shortMessage);
  assert.equal(
    keys.publicKey.toString('hex'),
    '1b20188d8c34d3eb09ffdcf15e726d3fea7b9cd6732ef0ed68d9ad20b9361816fa4657cecd07',
  );
  assert.equal(
    signature.toString('hex'),
    'e4b729c702d1c1b1c452d9e5dc7addd26e4bd2ab833d0448c198ba0aca92f40caf68baed3416' +
      '535e7eb51bc839bd760d92b10fb88481db70bba603cc71edd479dbe2a35134ddf18c80701300',
  );
});

test('normal signature verifies and is deterministic', () => {
  const keys = ed.keyGen(sequenceSeed);
  const a = ed.sign(sequenceSeed, shortContext, shortMessage.length, shortMessage);
  const b = ed.sign(sequenceSeed, shortContext, BigInt(shortMessage.length), shortMessage);
  assert.deepEqual(a, b);
  assert.equal(a.length, 76);
  assert.ok(ed.verify(keys.publicKey, shortContext, shortMessage.length, shortMessage, a));
});

test('buffered and chunked one-pass signing are byte-identical', () => {
  const message = crypto.createHash('sha512').update('ED301 long test').digest();
  const repeated = Buffer.concat(Array.from({ length: 1024 }, () => message));
  const chunks = [];
  for (let offset = 0; offset < repeated.length; offset += 137) {
    chunks.push(repeated.subarray(offset, Math.min(offset + 137, repeated.length)));
  }
  const buffered = ed.sign(sequenceSeed, shortContext, repeated.length, repeated);
  const streamed = ed.signChunks(sequenceSeed, shortContext, BigInt(repeated.length), chunks);
  const publicKey = ed.keyGen(sequenceSeed).publicKey;
  assert.deepEqual(streamed, buffered);
  assert.ok(ed.verifyChunks(publicKey, shortContext, BigInt(repeated.length), chunks, streamed));
});

test('maximum 255-byte context is accepted', () => {
  const context = Buffer.alloc(255, 0xa5);
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, context, 0n, empty);
  assert.ok(ed.verify(keys.publicKey, context, 0n, empty, signature));
});

test('256-byte context is rejected for sign and verify', () => {
  const context = Buffer.alloc(256);
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  throws(() => ed.sign(zeroSeed, context, 0n, empty), /context/);
  assert.equal(ed.verify(keys.publicKey, context, 0n, empty, signature), false);
});

test('seed length is exactly 38 bytes', () => {
  throws(() => ed.keyGen(Buffer.alloc(37)), /38/);
  throws(() => ed.keyGen(Buffer.alloc(39)), /38/);
  throws(() => ed.sign(Buffer.alloc(37), empty, 0n, empty), /38/);
});

test('announced message length must match actual bytes', () => {
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  throws(() => ed.sign(zeroSeed, empty, 2n, Buffer.from([1])), /shorter/);
  throws(() => ed.sign(zeroSeed, empty, 0n, Buffer.from([1])), /longer/);
  assert.equal(ed.verify(keys.publicKey, empty, 1n, empty, signature), false);
});

test('chunk iterator detects too few and too many bytes', () => {
  throws(() => ed.signChunks(zeroSeed, empty, 2n, [Buffer.from([1])]), /shorter/);
  throws(() => ed.signChunks(zeroSeed, empty, 0n, [Buffer.from([1])]), /longer/);
});

test('message, context, public-key, R, and S tampering is rejected', () => {
  const keys = ed.keyGen(sequenceSeed);
  const signature = ed.sign(sequenceSeed, shortContext, shortMessage.length, shortMessage);

  const alteredMessage = Buffer.from(shortMessage);
  alteredMessage[0] ^= 1;
  assert.equal(ed.verify(keys.publicKey, shortContext, alteredMessage.length, alteredMessage, signature), false);
  assert.equal(ed.verify(keys.publicKey, Buffer.from('other'), shortMessage.length, shortMessage, signature), false);

  const alteredKey = Buffer.from(keys.publicKey);
  alteredKey[0] ^= 1;
  assert.equal(ed.verify(alteredKey, shortContext, shortMessage.length, shortMessage, signature), false);

  const alteredR = Buffer.from(signature);
  alteredR[0] ^= 1;
  assert.equal(ed.verify(keys.publicKey, shortContext, shortMessage.length, shortMessage, alteredR), false);

  const alteredS = Buffer.from(signature);
  alteredS[38] ^= 1;
  assert.equal(ed.verify(keys.publicKey, shortContext, shortMessage.length, shortMessage, alteredS), false);
});

test('wrong public-key and signature lengths are rejected', () => {
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  assert.equal(ed.verify(keys.publicKey.subarray(1), empty, 0n, empty, signature), false);
  assert.equal(ed.verify(keys.publicKey, empty, 0n, empty, signature.subarray(1)), false);
  assert.equal(ed.verify(keys.publicKey, empty, 0n, empty, Buffer.concat([signature, Buffer.alloc(1)])), false);
});

test('S=q is rejected rather than reduced', () => {
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  C.q.toString();
  t.i2ospLE(C.q, 38).copy(signature, 38);
  assert.equal(ed.verify(keys.publicKey, empty, 0n, empty, signature), false);
});

test('identity, low-order, and mixed-order public keys are rejected', () => {
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  const identity = pointEncodingForY(1n);
  const orderTwo = pointEncodingForY(C.p - 1n);
  const p2 = t.decodePoint(orderTwo);
  const mixed = t.encodePoint(t.addPoints(t.basepoint, p2));
  for (const bad of [identity, orderTwo, mixed]) {
    assert.equal(ed.verify(bad, empty, 0n, empty, signature), false);
  }
});

test('identity and low-order commitments are rejected', () => {
  const keys = ed.keyGen(zeroSeed);
  const baseSignature = ed.sign(zeroSeed, empty, 0n, empty);
  for (const badR of [pointEncodingForY(1n), pointEncodingForY(C.p - 1n)]) {
    const signature = Buffer.concat([badR, baseSignature.subarray(38)]);
    assert.equal(ed.verify(keys.publicKey, empty, 0n, empty, signature), false);
  }
});

test('reserved bits in public key and commitment are rejected', () => {
  const keys = ed.keyGen(zeroSeed);
  const signature = ed.sign(zeroSeed, empty, 0n, empty);
  const badKey = Buffer.from(keys.publicKey);
  badKey[37] |= 0x20;
  assert.equal(ed.verify(badKey, empty, 0n, empty, signature), false);
  const badSignature = Buffer.from(signature);
  badSignature[37] |= 0x40;
  assert.equal(ed.verify(keys.publicKey, empty, 0n, empty, badSignature), false);
});

test('key-scalar zero causes retry with counter one', () => {
  const counters = [];
  const key = t.deriveKeyValues(zeroSeed, (frame, retry) => {
    counters.push({ retry, tail: frame.subarray(-4).toString('hex') });
    return retry === 0 ? 0n : 5n;
  });
  assert.equal(key.scalar, 5n);
  assert.equal(key.scalarRetry, 1);
  assert.deepEqual(counters, [
    { retry: 0, tail: '00000000' },
    { retry: 1, tail: '00000001' },
  ]);
});

test('nonce zero causes retry with counter one', () => {
  const counters = [];
  const result = t.signInjected(zeroSeed, empty, empty, {
    nonce: (frame, retry) => {
      counters.push({ retry, tail: frame.subarray(-4).toString('hex') });
      return retry === 0 ? 0n : 7n;
    },
  });
  assert.equal(result.nonce, 7n);
  assert.equal(result.nonceRetry, 1);
  assert.deepEqual(counters, [
    { retry: 0, tail: '00000000' },
    { retry: 1, tail: '00000001' },
  ]);
});

test('injected k=0 is accepted without retry', () => {
  const result = t.signInjected(zeroSeed, shortContext, shortMessage, {
    nonce: () => 9n,
    challenge: () => 0n,
  });
  assert.equal(result.challenge, 0n);
  assert.equal(result.response, 9n);
  assert.ok(t.verifyInjected(
    result.publicKey,
    shortContext,
    shortMessage,
    result.signature,
    () => 0n,
  ));
});

test('injected S=0 remains canonical and the equation decides', () => {
  const key = t.deriveKeyValues(zeroSeed);
  const nonce = 5n;
  const challenge = ((-nonce * t.invert(key.scalar, C.q)) % C.q + C.q) % C.q;
  const result = t.signInjected(zeroSeed, shortContext, shortMessage, {
    nonce: () => nonce,
    challenge: () => challenge,
  });
  assert.equal(result.response, 0n);
  assert.equal(result.signature.subarray(38).toString('hex'), '00'.repeat(38));
  assert.ok(t.verifyInjected(
    result.publicKey,
    shortContext,
    shortMessage,
    result.signature,
    () => challenge,
  ));
});

test('test injection hooks are absent from the normal module API by default', () => {
  const script = [
    "delete process.env.ED301_ENABLE_TEST_HOOKS;",
    "const e=require('./ed301_technischer_abschluss/gegenpruefung/ed301.js');",
    "process.exit(e.__testOnly === undefined ? 0 : 1);",
  ].join('');
  const result = require('node:child_process').spawnSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..', '..'),
  });
  assert.equal(result.status, 0, result.stderr.toString());
});

process.stdout.write(`# ${passed} passed, ${failures.length} failed\n`);
if (failures.length !== 0) process.exitCode = 1;

