# Ed301-EdDSA — unabhängige Python-Referenzimplementierung (Paket-A-blind)

**NICHT konstantzeitfähig. NICHT produktionstauglich.** Variable-time
Referenz ausschließlich zur Spezifikationsprüfung; niemals mit echten
Schlüsseln verwenden.

Erstellt am 2026-08-24 allein aus Paket A (Freeze-Commit `0c482948`), ohne
Internet, ohne fremden Code, ohne externe Testvektoren. Nur
Python-Standardbibliothek (`hashlib`, `secrets`, `sys`); getestet mit
Python 3.

## Dateien

| Datei | Inhalt |
| --- | --- |
| `ed301_eddsa.py` | Implementierung + Selbsttests (`python3 ed301_eddsa.py`) |
| `AMBIGUITIES.md` | Auslegungsprotokoll mit Quellenabschnitten |
| `README.md` | diese Beschreibung |
| `MANIFEST.sha256` | SHA-256 aller anderen Ergebnisdateien |

## Öffentliche Funktionen

| Funktion | Beschreibung |
| --- | --- |
| `generate_seed() -> bytes` | 38 zufällige Seed-Bytes (`secrets`), nur für Tests |
| `derive_public_key(seed) -> bytes` | 38-Byte-Public-Key `ENC([s]B)` (Draft §4) |
| `sign(seed, message) -> bytes` | 76-Byte-Signatur `ENC(R) \|\| ENC_SCALAR(S)` (Draft §5); Public Key wird aus dem Seed abgeleitet |
| `validate_public_key(pk) -> (x, y)` | kanonische Dekodierung plus `A != O`, `[L]A = O` (Draft §6); wirft `Ed301Error` |
| `verify(pk, message, signature) -> bool` | kofaktorisierte Prüfung `[4S]B = [4]R + [4k]A`; jede Parse-/Validierungsverletzung ergibt `False` |

Hilfsfunktionen (ebenfalls exportiert): `encode_point`, `decode_point`,
`encode_scalar`, `decode_scalar`, `encode_field`, `decode_field`,
`point_add`, `point_neg`, `scalar_mult`, `is_on_curve`,
`is_prime_subgroup_nonidentity`, `clear_cofactor`, `H`. Konstanten `P`, `A`,
`D_CURVE`, `L`, `N_ORDER`, `B_POINT`.

Alle Ein-/Ausgaben sind rohe `bytes`; es gibt keine Kontext-, Prehash-,
Hex- oder Container-Parameter (Draft §1, §7).

## Selbsttests

`python3 ed301_eddsa.py` führt beim Import die Basispunktprüfung
(`ENC(B)` reproduzierbar, `B != O`, `[L]B = O`) und anschließend 382
Prüfungen aus:

1. Parameterkonsistenz: Legendre-Symbole von `a`, `d`, `2`; `[L]B = [N]B = O`.
2. Torsionspunkte aus Extract §3.2 (`T2`, `T4±`, `1/45677 mod p`), Ordnungen,
   Ablehnung durch die strikte Untergruppenprüfung.
3. Kodierungen: Roundtrips für `O`, Torsion, `B`, `-B`, `[12345]B`;
   `SC(0)`, `SC(L-1)`; Ablehnung von `S = L`, `S = L+1`, falscher Länge,
   `x=0` mit Vorzeichen 1, reservierten Bits, `y = p`.
4. Sieben eigene Seeds (deterministische Muster, SHAKE-abgeleitete Seeds,
   ein Zufallsseed) × fünf eigene Nachrichten: Pruning-Eigenschaften von
   `s`, Determinismus, gültige Signatur, Ablehnung bei veränderter Nachricht,
   verändertem `R`, verändertem `S`, falscher Länge, `S = L`, fremdem
   Schlüssel.
5. Public-Key-Validierung: `O`, `T2`, `T4+`, `B + T2` werden abgelehnt.
6. Kofaktorisierte Gleichung: eine konstruierte Signatur mit `R' = R + T2`
   wird akzeptiert, während die nicht-kofaktorisierte Gleichung sie ablehnt;
   `R = O` wird geparst, die Gleichung schlägt fehl.

Es wurden keine externen Signaturbytes gesucht oder eingebaut. Die am Ende
ausgegebene Beispielsignatur stammt aus einem eigenen Seed (`00..25`) und
dient nur der späteren Gegenprüfung mit Paket B.
