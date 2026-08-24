# AMBIGUITIES.md — Auslegungsprotokoll zur Ed301-EdDSA-Referenzimplementierung

Grundlage: ausschließlich Paket A (Freeze-Commit `0c482948`). Quellen:
**Draft** = `ED301-EdDSA-draft.md`, **Extract** = `ED301-v1-EdDSA-extract.md`,
**JSON** = `ed301-v1.json`, **RFC** = `RFC8032-Section3.txt`.
Vorrangregel laut `A_PROVENANCE.txt`: der Draft geht dem RFC vor, wo er eine
speziellere Regel angibt.

Jeder Eintrag: Fundstelle → Problem → mögliche Lesarten → vorläufig gewählte
Lesart. Die Nummern `[A-n]` werden im Code referenziert.

---

## A-1 Skalarbereich in Signaturen: RFC „0 < S < L-1“ vs. Draft „0 <= S < L“

- RFC §3.1: „An integer 0 < S < L - 1 is encoded …“; RFC §3.4: S ∈ {0,…,L-1}.
  Der RFC ist hier intern uneinheitlich.
- Draft §3.2 und §6, Extract §9.2, JSON `/encoding/signature_scalar_range`:
  `0 <= S < L`, `S(0)` und `S(L-1)` gültig, `S >= L` verworfen.
- **Gewählt:** `0 <= S < L` (Draft/Extract). Keine Reduktion bei `S >= L`.

## A-2 Feldkodierung „303-bit“ (Draft §2, RFC Param. 3) vs. 38-Byte-Kodierung mit Bits 301..303 = 0 (Extract §9.1)

- Der RFC verlangt eine `(b-1)` = 303-Bit-Feldkodierung; der Draft nennt sie
  „canonical 303-bit little-endian field encoding“. Der Extract definiert
  `FE(x)` als 38 Byte mit Wert in Bits 0..300 und Bits 301..303 = 0.
- Lesarten: (a) beides identisch, da `p < 2^301` und die 303-Bit-Kodierung
  innerhalb der ersten 38 Byte liegt, Bit 303 bleibt für das Vorzeichen frei;
  (b) formal verschiedene Objekte.
- **Gewählt:** (a). Für Punkte gilt Draft §3.1/Extract §9.3: Bits 301, 302
  müssen 0 sein, Bit 303 ist das Vorzeichen; Prüfung `b[37] & 0x60 == 0`.
  Ein reines Feldelement (`decode_field`) prüft `b[37] & 0xe0 == 0`.
  `decode_field` wird von der Signatur-API nicht benötigt, ist aber enthalten.

## A-3 „Negatives“ x: RFC-lexikographische Definition vs. Draft `LSB(x)=1`

- RFC §3.1 definiert das Vorzeichenbit über lexikographischen Vergleich der
  Feldkodierungen von `x` und `-x`. Draft §3.1 und Extract §9.3 setzen
  Bit 303 = `x & 1`.
- Nachvollzogen: Bit 0 ist das erste Bit der LE-Kodierung; `x` und `p-x`
  haben bei ungeradem `p` verschiedene Parität, also entscheidet Bit 0.
  Kein Widerspruch, die Regeln sind äquivalent (RFC-Bit-Reihenfolge
  „Bit 0 zuerst“ vorausgesetzt).
- **Gewählt:** `x & 1`. Bei `x = 0` ist nur Vorzeichen 0 kanonisch
  (Draft §3.1, Extract §9.3 Schritt 5).

## A-4 Zusätzliche Kanonizitätsprüfung: „Re-Encoding muss Eingabe exakt reproduzieren“

- Draft §3.1 verlangt, dass das Re-Encoding eines dekodierten Punktes die
  Eingabe exakt reproduziert. Der Extract §9.3 hat diese Regel nicht explizit,
  aber seine Schritte 1–6 erzwingen bereits Kanonizität (reservierte Bits,
  `y < p`, `x=0`-Regel).
- Lesarten: (a) Re-Encoding-Vergleich ist redundante Sicherung; (b) er ist
  eine zusätzliche, potenziell strengere Regel.
- **Gewählt:** Beides implementiert — Extract-Schritte plus abschließender
  Byte-Vergleich in `decode_point`. Nach meinem Verständnis kann der
  Vergleich nach den Extract-Prüfungen nie fehlschlagen; er ist als
  Defensive-Check enthalten.

## A-5 Nonce-Hash und Challenge-Hash: Reduktion mod L (Draft §5) vs. volle 608-Bit-Integer (RFC §3.3)

- RFC: `r = H(prefix || M)` als 608-Bit-Integer, `R = [r]B`,
  `S = (r + H(...)*s) mod L`. Draft §5: `r = LE_INTEGER(...) mod L`,
  `k = LE_INTEGER(...) mod L`, mit der Aussage, dies sei byte-äquivalent.
- Nachvollzogen: `[r]B = [r mod L]B`, da `B` Ordnung `L` hat; `S` ist ohnehin
  mod `L`. Äquivalent.
- **Gewählt:** Reduktion mod `L` wie im Draft.

## A-6 Verifikation: `k` in der Gleichung reduziert mod L

- Draft §6: `k = ... mod L`, Gleichung `[4S]B = [4]R + [4k]A`. RFC §3.4
  nutzt `h` unreduziert. Da `A` als Primuntergruppenpunkt (Ordnung `L`)
  validiert wird, gilt `[4h]A = [4(h mod L)]A`.
- **Gewählt:** `k mod L` gemäß Draft. Ohne die Public-Key-Validierung wäre
  dies nicht äquivalent — die Validierung wird daher nie übersprungen.

## A-7 Verwendung der Signaturbytes `Renc` im Challenge-Hash

- Draft §5/§6 hashen `Renc || public_key || M`. Frage: die empfangenen Bytes
  oder das Re-Encoding des dekodierten `R`?
- Da `decode_point` nur kanonische Kodierungen akzeptiert (A-4), sind beide
  identisch.
- **Gewählt:** die empfangenen Signaturbytes und die empfangenen
  Public-Key-Bytes werden unverändert gehasht.

## A-8 Prüfung von `R`: keine Untergruppenprüfung, Identität erlaubt

- Draft §6/§8: `R` wird nur als kanonischer Punkt dekodiert; `R = O`,
  Primuntergruppen-`R` und gemischte Torsion sind syntaktisch zulässig.
  RFC §3.4: „R element of E“ — konsistent.
- **Gewählt:** keine `[L]R = O`-Prüfung, keine Identitätsprüfung für `R`.
  Der Selbsttest bestätigt, dass eine Signatur mit `R' = R + T2` unter der
  kofaktorisierten Gleichung akzeptiert und unter einer nicht-kofaktorisierten
  Gleichung verworfen würde.

## A-9 Public-Key-Validierung im Verifizierer: Reihenfolge und Fehlerverhalten

- Draft §6: Public-Key-Validierung und Signatur-Parsing sind „logisch
  getrennt“; beide Bedingungen (`A != O`, `[L]A = O`) dürfen nicht entfallen.
- Lesarten: (a) ungültiger Public Key → Ausnahme; (b) → `verify` liefert
  `False`.
- **Gewählt:** `validate_public_key()` wirft `Ed301Error` (für Aufrufer, die
  Schlüssel vorab prüfen/cachen); `verify()` fängt alle `Ed301Error` ab und
  liefert `False`. Kein Caching implementiert.

## A-10 Seed-Länge und Private-Key-Begriff

- RFC §3.2: Private Key ist ein `b`-Bit-String = 304 Bit = 38 Byte.
  Draft §4: „exactly 38 uniformly random seed bytes“.
- **Gewählt:** Seed exakt 38 Byte; andere Längen → Fehler. Es gibt keinen
  weiteren Private-Key-Container (Draft §1 schließt Container-Formate aus).

## A-11 Pruning-Regel und Bitpositionen

- Draft §4: `lower[0] &= 0xfc`, `lower[37] = (lower[37] & 0x0f) | 0x10`.
  RFC §3.2: `s = 2^n + Σ 2^i h_i` für `c <= i < n` mit `n=300`, `c=2`.
- Nachgerechnet: Bit 300 = Byte 37, Bit 4 (`0x10`); `& 0x0f` löscht Bits
  300..303, `| 0x10` setzt Bit 300; `& 0xfc` löscht Bits 0,1. Deckungsgleich
  mit dem RFC.
- **Gewählt:** Draft-Bytefolge wörtlich. `s >= L` ist möglich (`s ~ 2^300`,
  `L < 2^300`); der Draft verlangt keine Reduktion von `s`; `[s]B` und
  `S = (r + k*s) mod L` sind davon unabhängig. Keine Reduktion vorgenommen.

## A-12 Ableitung des Public Keys beim Signieren

- Draft §4: Signier-API leitet `public_key` aus dem Seed ab oder prüft einen
  gecachten Wert gegen diese Ableitung.
- **Gewählt:** `sign(seed, message)` leitet `public_key` immer neu ab; es gibt
  keine Möglichkeit, einen fremden Public Key einzuschleusen.

## A-13 Quadratwurzel und Nichtquadrat-Prüfung

- Draft §3.1 sagt nur „the right side must be a square“; das Verfahren
  liefert der Extract §3.1/§9.3: `r = x2^((p+1)/4)`, Prüfung `r^2 = x2`.
- **Gewählt:** Extract-Verfahren. `x2 = 0` (nur bei `y = ±1`) ergibt `r = 0`.

## A-14 Nullnenner bei der x-Rückgewinnung

- Extract §9.3 Schritt 3: `a - d*y^2 = 0` → Fehler. Da `d` Nichtquadrat und
  `a` Quadrat ist, ist `a/d` kein Quadrat und der Fall kann für `y in F_p`
  nicht eintreten; die Prüfung ist trotzdem implementiert.

## A-15 Nullnenner in der Punktaddition

- Extract §4.2: Formel ist vollständig; Implementierung SOLLTE Nullnenner
  dennoch als internen Fehler erkennen.
- **Gewählt:** `point_add` wirft `Ed301Error` bei `dx == 0` oder `dy == 0`.
  In `verify` würde dies zu `False` führen; da der Fall für gültige Punkte
  ausgeschlossen ist, hat das keine Auswirkung auf die Signatursprache.

## A-16 „H(X) = first 76 octets of SHAKE256(X)“ vs. `SHAKE256(X, 76)`

- Draft §2 und §4/§5 verwenden beide Schreibweisen.
- SHAKE256 ist eine XOF; eine Ausgabe der Länge 76 ist per Definition das
  Präfix der unendlichen Ausgabe. Identisch.
- **Gewählt:** `hashlib.shake_256(X).digest(76)`.

## A-17 Public Key als Bytes: nur die 38-Byte-Kodierung ist normativ

- Draft §4: `public_key = ENC(A)`; keine weiteren Formate.
- **Gewählt:** Alle API-Funktionen arbeiten mit rohen 38-Byte-Public-Keys
  und 76-Byte-Signaturen; keine Hex-/ASN.1-/OID-Behandlung.

## A-18 Basispunkt: nur komprimiert gegeben

- Draft §3.1 und JSON `/basepoint/G_compressed_edwards_hex` geben nur die
  komprimierte Kodierung; affine Koordinaten sind in Paket A redigiert.
- **Gewählt:** `B` wird beim Import mit der eigenen `decode_point`
  dekodiert; anschließend werden `ENC(B) == Eingabe`, `B != O` und
  `[L]B = O` geprüft (Modulimport schlägt sonst fehl). Die Ordnung `L`
  konnte damit unabhängig bestätigt werden.

## A-19 Verifikation: `[4]R + [4k]A` — Reihenfolge/Assoziation

- Draft §6 schreibt `[4]R + [4k]A`. Da die Addition kommutativ und die
  affine Formel vollständig ist, spielt die Reihenfolge keine Rolle.
- **Gewählt:** `point_add([4]R, [4k]A)`; `[4S]B` separat.

## A-20 Nachrichtentyp und Kontext

- Draft §7: kein `dom`, kein Kontext, kein Prehash; `M` ist ein opaker
  Bytestring; Domain-Separation gehört in `M`.
- **Gewählt:** `message` muss `bytes`/`bytearray` sein; kein Kontext- oder
  Prehash-Parameter existiert in der API, damit er nicht versehentlich
  ignoriert werden kann (Draft §7, letzter Absatz).

## A-21 Nicht beobachtete Unklarheiten (Vollständigkeitsvermerk)

Keine Widersprüche gefunden zwischen Draft, Extract und JSON bei `p`, `a`,
`d`, `N`, `q=L`, `h=4`, Bitlängen, Kodierungslayout, Basispunkt-Encoding und
Torsionspunkten. Der Wert `1/45677 mod p` aus dem Extract wurde nachgerechnet
und stimmt. `45677^2 = 2086388329` ohne Reduktion.

## Bewusste Nicht-Implementierungen

- Keine Konstantzeit-Arithmetik, keine Zeroization, kein Fehlerinjektions-
  schutz (Draft §8) — ausdrücklich außerhalb des Auftrags.
- Kein Montgomery-/Weierstraß-Modell, keine x-only-Leiter (in Paket A
  redigiert und für EdDSA nicht benötigt).
- Kein Streaming-/Inkremental-Signieren, kein Batch-Verify.
