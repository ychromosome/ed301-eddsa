#!/usr/bin/env python3
"""
Ed301-EdDSA -- unabhaengige, variable-time Python-Referenzimplementierung.

WARNUNG
=======
NICHT KONSTANTZEITFAEHIG.  NICHT PRODUKTIONSTAUGLICH.  NUR ZUR SPEZIFIKATIONS-
PRUEFUNG.  Python-Integer-Arithmetik, affine Punktaddition mit modularer
Inversion, Double-and-Add-Skalarmultiplikation und alle Vergleiche laufen in
datenabhaengiger Zeit.  Keine Zeroization, keine Fehlerinjektionsabwehr.
Niemals mit echten Schluesseln verwenden.

Grundlage
=========
Ausschliesslich Paket A des spezifikationsblinden Experiments
(Freeze-Commit 0c48294893e9b7ec46109de51c3a04829befb39f):
  - ED301-EdDSA-draft.md            (draft 00)          -> "Draft"
  - ED301-v1-EdDSA-extract.md       (ED301-v1 Extract)  -> "Extract"
  - ed301-v1.json                   (redigiert)         -> "JSON"
  - RFC8032-Section3.txt            (RFC 8032 Abschnitt 3 bis 3.4) -> "RFC"
Kein weiterer Code, keine externen Testvektoren, kein Internet.
Auslegungsentscheidungen sind in AMBIGUITIES.md dokumentiert; Verweise der
Form [A-n] beziehen sich auf die dortigen Eintraege.

Nur Python-Standardbibliothek (hashlib, secrets, sys).
"""

import hashlib
import secrets
import sys

# ---------------------------------------------------------------------------
# 1. Feste Parameter (Draft §2, Extract §3.1/§3.2, JSON)
# ---------------------------------------------------------------------------

P = 2**301 - 2**99 + 947
assert P == 4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011
assert P == 0x1ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000003b3
assert P.bit_length() == 301 and P % 8 == 3

A = 2086388329                      # = 45677^2 (Extract §3.1)
assert A == 45677 * 45677 % P
D_CURVE = 301                       # Kurvenkoeffizient d (Draft nennt ihn d_curve)

N_ORDER = 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612
L = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403
assert L == 0x800000000000000000000000000000000000016dcc80892809847fb4a312602e3a1d0be9603
assert N_ORDER == 4 * L
assert L.bit_length() == 300 and L % 2 == 1
COFACTOR = 4

# RFC-Parameter des Drafts
B_BITS = 304                        # b
C_RFC = 2                           # c
N_RFC = 300                         # n
FIELD_BYTES = 38
POINT_BYTES = 38
SCALAR_BYTES = 38
HASH_BYTES = 76                     # H(X) = erste 76 Oktette von SHAKE256(X)
SEED_BYTES = 38
PUBLIC_KEY_BYTES = 38
SIGNATURE_BYTES = 76

# Basispunkt: nur die komprimierte Kodierung ist normativ gegeben
# (Draft §3.1, JSON /basepoint). Er wird unten dekodiert und geprueft.
G_COMPRESSED_HEX = "6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898"

IDENTITY = (0, 1)


class Ed301Error(ValueError):
    """Dekodier-, Validierungs- oder Verifikationsfehler."""


# ---------------------------------------------------------------------------
# 2. Feldarithmetik (variable-time)
# ---------------------------------------------------------------------------

def _inv(x):
    """Multiplikative Inverse in F_p. Null ist ein Fehler (Extract §4.2)."""
    x %= P
    if x == 0:
        raise Ed301Error("Inversion von 0 in F_p")
    return pow(x, P - 2, P)


def _sqrt(w):
    """Quadratwurzel fuer p mod 4 = 3 (Extract §3.1 / §9.3 Schritt 4).
    Gibt None zurueck, wenn w kein Quadrat ist."""
    w %= P
    r = pow(w, (P + 1) // 4, P)
    if r * r % P != w:
        return None
    return r


# ---------------------------------------------------------------------------
# 3. Kurvenarithmetik (Extract §4, RFC §3) -- affin, vollstaendig, variable-time
# ---------------------------------------------------------------------------

def is_on_curve(pt):
    """Kanonischer ED301-Punkt: 0 <= x,y < p und Kurvengleichung (Extract §4.1)."""
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (A * x * x + y * y - 1 - D_CURVE * x * x * y * y) % P == 0


def point_neg(pt):
    x, y = pt
    return ((-x) % P, y)


def point_add(p1, p2):
    """Vollstaendige affine Addition (Extract §4.2, RFC §3)."""
    x1, y1 = p1
    x2, y2 = p2
    e = D_CURVE * x1 * x2 % P * y1 % P * y2 % P
    dx = (1 + e) % P
    dy = (1 - e) % P
    if dx == 0 or dy == 0:
        # Laut Extract §4.2 fuer gueltige Punkte unmoeglich; als internen
        # Fehler melden statt stillschweigend fortzufahren.
        raise Ed301Error("Nullnenner in der Punktaddition (interner Fehler)")
    x3 = (x1 * y2 + y1 * x2) % P * _inv(dx) % P
    y3 = (y1 * y2 - A * x1 * x2) % P * _inv(dy) % P
    return (x3, y3)


def point_double(pt):
    return point_add(pt, pt)


def scalar_mult(k, pt):
    """[k]P per Double-and-Add fuer k >= 0; [0]P = O (Extract §4.2).
    Variable-time -- ausdruecklich kein Seitenkanalschutz."""
    if k < 0:
        raise Ed301Error("negativer Skalar")
    result = IDENTITY
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result


def point_equal(p1, p2):
    return p1[0] % P == p2[0] % P and p1[1] % P == p2[1] % P


# ---------------------------------------------------------------------------
# 4. Kodierungen (Draft §3, Extract §9)
# ---------------------------------------------------------------------------

def encode_field(x):
    """FE(x): 38 Byte little-endian, 0 <= x < p (Extract §9.1)."""
    if not (0 <= x < P):
        raise Ed301Error("Feldelement ausserhalb 0..p-1")
    return x.to_bytes(FIELD_BYTES, "little")


def decode_field(b):
    """Strikt: exakt 38 Byte, Bits 301..303 null, x < p; keine Reduktion."""
    if len(b) != FIELD_BYTES:
        raise Ed301Error("Feldelement: falsche Laenge")
    if b[37] & 0xE0:
        raise Ed301Error("Feldelement: reservierte Bits gesetzt")
    x = int.from_bytes(b, "little")
    if x >= P:
        raise Ed301Error("Feldelement: x >= p")
    return x


def encode_point(pt):
    """ENC(x,y): FE(y) mit Bit 303 = x & 1 (Draft §3.1, Extract §9.3)."""
    x, y = pt
    if not is_on_curve(pt):
        raise Ed301Error("ENC: kein kanonischer Kurvenpunkt")
    enc = bytearray(encode_field(y))
    enc[37] |= (x & 1) << 7
    return bytes(enc)


def decode_point(b):
    """Kanonische Punktdekodierung (Extract §9.3 Schritte 1-6, Draft §3.1).
    Akzeptiert Identitaet und Torsion; KEINE Untergruppenpruefung."""
    if len(b) != POINT_BYTES:
        raise Ed301Error("ENC: falsche Laenge")
    if b[37] & 0x60:
        raise Ed301Error("ENC: reservierte Bits 301/302 gesetzt")
    sign = (b[37] >> 7) & 1
    yb = bytearray(b)
    yb[37] &= 0x7F
    y = int.from_bytes(yb, "little")
    if y >= P:
        raise Ed301Error("ENC: y >= p")
    y2 = y * y % P
    denominator = (A - D_CURVE * y2) % P
    if denominator == 0:
        raise Ed301Error("ENC: Nullnenner bei x-Rueckgewinnung")
    x2 = (1 - y2) % P * _inv(denominator) % P
    r = _sqrt(x2)
    if r is None:
        raise Ed301Error("ENC: x^2 ist kein Quadrat")
    if r == 0:
        if sign != 0:
            raise Ed301Error("ENC: x=0 mit Vorzeichenbit 1 ist ungueltig")
        x = 0
    else:
        x = r if (r & 1) == sign else (P - r)
    pt = (x, y)
    if not is_on_curve(pt):
        raise Ed301Error("ENC: Punkt erfuellt Kurvengleichung nicht")
    # Draft §3.1: Re-Encoding muss die Eingabe exakt reproduzieren.
    if encode_point(pt) != bytes(b):
        raise Ed301Error("ENC: nicht kanonisch (Re-Encoding weicht ab)")  # [A-4]
    return pt


def encode_scalar(s):
    """ENC_SCALAR(S): exakt 38 Byte little-endian, 0 <= S < L (Draft §3.2)."""
    if not (0 <= s < L):
        raise Ed301Error("Skalar ausserhalb 0..L-1")
    return s.to_bytes(SCALAR_BYTES, "little")


def decode_scalar(b):
    """Exakt 38 Byte, S < L; S >= L wird verworfen, nie reduziert."""
    if len(b) != SCALAR_BYTES:
        raise Ed301Error("Skalar: falsche Laenge")
    s = int.from_bytes(b, "little")
    if s >= L:
        raise Ed301Error("Skalar: S >= L")
    return s


# ---------------------------------------------------------------------------
# 5. Hash und Untergruppe
# ---------------------------------------------------------------------------

def H(data):
    """H(X) = erste 76 Oktette von SHAKE256(X) (Draft §2)."""
    return hashlib.shake_256(data).digest(HASH_BYTES)


def clear_cofactor(pt):
    return scalar_mult(COFACTOR, pt)


def is_prime_subgroup_nonidentity(pt):
    """Strikte Pruefung: P != O und [L]P = O (Extract §8, Draft §6)."""
    if point_equal(pt, IDENTITY):
        return False
    return point_equal(scalar_mult(L, pt), IDENTITY)


# Basispunkt dekodieren und beim Import pruefen
B_POINT = decode_point(bytes.fromhex(G_COMPRESSED_HEX))
assert encode_point(B_POINT) == bytes.fromhex(G_COMPRESSED_HEX)
assert is_prime_subgroup_nonidentity(B_POINT), "Basispunkt hat nicht Ordnung L"


# ---------------------------------------------------------------------------
# 6. Oeffentliche API
# ---------------------------------------------------------------------------

def generate_seed():
    """38 gleichverteilt zufaellige Seed-Bytes (Draft §4). Nur fuer Tests."""
    return secrets.token_bytes(SEED_BYTES)


def _expand_seed(seed):
    """Liefert (s, prefix) gemaess Draft §4 / RFC §3.2."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_BYTES:
        raise Ed301Error("Seed muss exakt 38 Byte lang sein")
    h = H(bytes(seed))
    lower = bytearray(h[0:38])
    prefix = h[38:76]
    lower[0] &= 0xFC                              # Bits 0,1 loeschen (c=2)
    lower[37] = (lower[37] & 0x0F) | 0x10         # Bits 301..303 loeschen, Bit 300 setzen
    s = int.from_bytes(lower, "little")
    assert 2**300 <= s < 2**301 and s % 4 == 0
    return s, prefix


def derive_public_key(seed):
    """public_key = ENC([s]B) (Draft §4)."""
    s, _ = _expand_seed(seed)
    A_pt = scalar_mult(s, B_POINT)
    return encode_point(A_pt)


def sign(seed, message):
    """PureEdDSA-Signatur (Draft §5), 76 Byte = ENC(R) || ENC_SCALAR(S).
    Der oeffentliche Schluessel wird stets aus dem Seed abgeleitet (Draft §4).
    """
    if not isinstance(message, (bytes, bytearray)):
        raise Ed301Error("Nachricht muss bytes sein")
    message = bytes(message)
    s, prefix = _expand_seed(seed)
    public_key = encode_point(scalar_mult(s, B_POINT))
    r = int.from_bytes(H(prefix + message), "little") % L
    R = scalar_mult(r, B_POINT)
    Renc = encode_point(R)
    k = int.from_bytes(H(Renc + public_key + message), "little") % L
    S = (r + k * s) % L
    return Renc + encode_scalar(S)


def validate_public_key(public_key):
    """Dekodiert A kanonisch und verlangt A != O und [L]A = O (Draft §6).
    Gibt den validierten Punkt zurueck."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        raise Ed301Error("Public Key muss exakt 38 Byte lang sein")
    A_pt = decode_point(bytes(public_key))
    if not is_prime_subgroup_nonidentity(A_pt):
        raise Ed301Error("Public Key ist Identitaet oder nicht in der Primuntergruppe")
    return A_pt


def verify(public_key, message, signature):
    """Kofaktorisierte Verifikation (Draft §6): [4S]B = [4]R + [4k]A.
    Gibt True/False zurueck; Parsefehler ergeben False."""
    try:
        if not isinstance(message, (bytes, bytearray)):
            return False
        message = bytes(message)
        A_pt = validate_public_key(public_key)
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_BYTES:
            return False
        signature = bytes(signature)
        Renc, Senc = signature[:38], signature[38:]
        R = decode_point(Renc)        # nur kanonische Punktsyntax, kein [L]R = O
        S = decode_scalar(Senc)
        k = int.from_bytes(H(Renc + bytes(public_key) + message), "little") % L
        lhs = scalar_mult(4 * S, B_POINT)
        rhs = point_add(scalar_mult(4, R), scalar_mult(4 * k, A_pt))
        return point_equal(lhs, rhs)
    except Ed301Error:
        return False


# ---------------------------------------------------------------------------
# 7. Selbsttests (eigene, neu gewaehlte Seeds/Nachrichten; keine externen Vektoren)
# ---------------------------------------------------------------------------

def _selftest():
    ok = 0

    def check(cond, name):
        nonlocal ok
        if not cond:
            raise AssertionError("Selbsttest fehlgeschlagen: " + name)
        ok += 1

    # 7.1 Parameter- und Kurvenkonsistenz
    check(pow(A, (P - 1) // 2, P) == 1, "Legendre(a)=1")
    check(pow(D_CURVE, (P - 1) // 2, P) == P - 1, "Legendre(d)=-1")
    check(pow(2, (P - 1) // 2, P) == P - 1, "2 ist Nichtrest")
    check(is_on_curve(IDENTITY), "Identitaet auf Kurve")
    check(is_on_curve(B_POINT), "Basispunkt auf Kurve")
    check(point_equal(scalar_mult(L, B_POINT), IDENTITY), "[L]B = O")
    check(point_equal(scalar_mult(N_ORDER, B_POINT), IDENTITY), "[N]B = O")

    # 7.2 Torsionspunkte aus Extract §3.2
    inv45677 = _inv(45677)
    check(inv45677 == 2519704285809016876637414484207147275421064523548512340148037688179123305227756371005740363,
          "1/45677 mod p stimmt mit Extract")
    T2 = (0, P - 1)
    T4p = (inv45677, 0)
    T4m = ((-inv45677) % P, 0)
    for T in (T2, T4p, T4m):
        check(is_on_curve(T), "Torsionspunkt auf Kurve")
    check(point_equal(point_double(T2), IDENTITY), "T2 Ordnung 2")
    check(point_equal(point_double(T4p), T2), "[2]T4+ = T2")
    check(point_equal(point_add(T4p, T4m), IDENTITY), "T4+ + T4- = O")
    check(point_equal(scalar_mult(4, T4p), IDENTITY), "T4+ Ordnung 4")
    check(not is_prime_subgroup_nonidentity(T2), "T2 nicht in Primuntergruppe")
    check(not is_prime_subgroup_nonidentity(IDENTITY), "O nicht akzeptiert")

    # 7.3 Kodierungs-Roundtrips
    for pt in (IDENTITY, T2, T4p, T4m, B_POINT, point_neg(B_POINT), scalar_mult(12345, B_POINT)):
        check(decode_point(encode_point(pt)) == pt, "Punkt-Roundtrip")
    check(encode_point(IDENTITY) == b"\x01" + b"\x00" * 37, "ENC(O)")
    check(decode_scalar(encode_scalar(0)) == 0, "SC(0)")
    check(decode_scalar(encode_scalar(L - 1)) == L - 1, "SC(L-1)")
    for bad in (encode_scalar(0)[:37], (L).to_bytes(38, "little"), (L + 1).to_bytes(38, "little")):
        try:
            decode_scalar(bad)
            check(False, "ungueltiger Skalar akzeptiert")
        except Ed301Error:
            check(True, "ungueltiger Skalar verworfen")
    # x=0 mit Sign-Bit 1 (Identitaet mit gesetztem Bit 303) ist ungueltig
    bad_id = bytearray(encode_point(IDENTITY)); bad_id[37] |= 0x80
    try:
        decode_point(bytes(bad_id)); check(False, "x=0/sign=1 akzeptiert")
    except Ed301Error:
        check(True, "x=0/sign=1 verworfen")
    # reservierte Bits
    bad_res = bytearray(encode_point(B_POINT)); bad_res[37] |= 0x20
    try:
        decode_point(bytes(bad_res)); check(False, "reserviertes Bit akzeptiert")
    except Ed301Error:
        check(True, "reserviertes Bit verworfen")
    # y >= p (y = p kodiert, Bits 301..303 = 0 da p < 2^301)
    try:
        decode_point(P.to_bytes(38, "little")); check(False, "y=p akzeptiert")
    except Ed301Error:
        check(True, "y=p verworfen")

    # 7.4 Schluesselableitung, Signieren, Verifizieren mit eigenen Seeds
    seeds = [
        bytes(range(38)),
        bytes([0xA5] * 38),
        bytes([0x00] * 38),
        bytes([0xFF] * 38),
        hashlib.shake_256(b"ED301 blind experiment self-test seed 1").digest(38),
        hashlib.shake_256(b"ED301 blind experiment self-test seed 2").digest(38),
        generate_seed(),
    ]
    messages = [b"", b"a", b"Ed301-EdDSA Selbsttest", bytes(range(256)), b"x" * 1000]
    for seed in seeds:
        s, prefix = _expand_seed(seed)
        check(s.bit_length() == 301 and s % 4 == 0, "Skalar-Pruning")
        check(s % L != 0, "s nicht Vielfaches von L")
        pk = derive_public_key(seed)
        check(len(pk) == 38, "PK-Laenge")
        validate_public_key(pk)
        for m in messages:
            sig = sign(seed, m)
            check(len(sig) == 76, "Signaturlaenge")
            check(sign(seed, m) == sig, "deterministisch")
            check(verify(pk, m, sig), "gueltige Signatur")
            check(not verify(pk, m + b"\x00", sig), "veraenderte Nachricht")
            bad = bytearray(sig); bad[0] ^= 1
            check(not verify(pk, m, bytes(bad)), "veraendertes R")
            bad = bytearray(sig); bad[38] ^= 1
            check(not verify(pk, m, bytes(bad)), "veraendertes S")
            check(not verify(pk, m, sig[:75]), "Signatur zu kurz")
            check(not verify(pk, m, sig + b"\x00"), "Signatur zu lang")
            # S >= L im Signaturfeld
            bad = sig[:38] + L.to_bytes(38, "little")
            check(not verify(pk, m, bad), "S = L verworfen")
    # Fremder Schluessel
    check(not verify(derive_public_key(seeds[0]), b"m", sign(seeds[1], b"m")), "falscher Schluessel")

    # 7.5 Public-Key-Validierung
    for bad_pk in (encode_point(IDENTITY), encode_point(T2), encode_point(T4p),
                   encode_point(point_add(B_POINT, T2))):
        check(not verify(bad_pk, b"m", b"\x00" * 76), "ungueltiger PK abgelehnt")
        try:
            validate_public_key(bad_pk); check(False, "validate akzeptiert Torsion/Identitaet")
        except Ed301Error:
            check(True, "validate lehnt ab")

    # 7.6 Kofaktorisierte Gleichung: R mit Torsionsanteil bleibt akzeptiert,
    #      wenn die Gleichung erfuellt ist (Draft §6). Konstruktion:
    #      R' = R + T2 (Torsionsanteil), S unveraendert, aber k haengt von
    #      ENC(R') ab -> hier eine Signatur direkt mit R' bauen.
    seed = seeds[0]
    s, prefix = _expand_seed(seed)
    pk = derive_public_key(seed)
    m = b"torsion"
    r = int.from_bytes(H(prefix + m), "little") % L
    Rp = point_add(scalar_mult(r, B_POINT), T2)
    Rpenc = encode_point(Rp)
    k = int.from_bytes(H(Rpenc + pk + m), "little") % L
    S = (r + k * s) % L
    sig_t = Rpenc + encode_scalar(S)
    check(verify(pk, m, sig_t), "R mit Torsionsanteil, kofaktorisiert akzeptiert")
    check(sig_t != sign(seed, m), "Torsionssignatur unterscheidet sich")
    # uncofactored Gleichung wuerde dies verwerfen (Draft §6, nur zur Illustration)
    A_pt = validate_public_key(pk)
    lhs = scalar_mult(S, B_POINT)
    rhs = point_add(Rp, scalar_mult(k, A_pt))
    check(not point_equal(lhs, rhs), "uncofactored Gleichung lehnt Torsions-R ab")
    # R = O syntaktisch erlaubt (Draft §6); Gleichung wird i.d.R. nicht erfuellt
    check(not verify(pk, m, encode_point(IDENTITY) + encode_scalar(1)), "R=O geparst, Gleichung falsch")

    return ok


if __name__ == "__main__":
    n = _selftest()
    print("Ed301-EdDSA Referenzimplementierung (variable-time, NICHT produktionstauglich)")
    print("Selbsttests bestanden: %d Pruefungen" % n)
    seed = bytes(range(38))
    pk = derive_public_key(seed)
    sig = sign(seed, b"Ed301-EdDSA Selbsttest")
    print("Beispiel (eigener Seed 00..25, Nachricht 'Ed301-EdDSA Selbsttest'):")
    print("  public_key =", pk.hex())
    print("  signature  =", sig.hex())
    sys.exit(0)
