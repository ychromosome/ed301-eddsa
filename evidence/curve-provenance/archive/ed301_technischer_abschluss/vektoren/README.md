# Ed301-Sig-v1-Testvektoren

## Status und Zweck

Dieses Verzeichnis enthält reproduzierbare Konformitäts- und Negativvektoren
für die technische Begutachtung von `Ed301-Sig-v1`. Sie wurden aus der
bytegenauen Spezifikation, dem normativen Parametersatz und der
Python-Referenz erzeugt. Sie sind **kein Produktionsaudit**, kein Nachweis von
Seitenkanalresistenz und keine Freigabe für produktive Kryptographie.

## Dateien

- `ed301-sig-v1-positive.json` enthält fünf positive Vektoren. Abgedeckt sind
  leere, kurze, binäre und lange Nachrichten, Kontextlängen 0, nichtleer und
  exakt 255 Byte sowie eine vollständige deterministische Wiederholung.
- `ed301-sig-v1-negative.json` enthält gewöhnliche Verifikationseingaben mit
  dem erwarteten Ergebnis `false`. Null-/Retry- und reine Framingprüfungen
  stehen bewusst getrennt unter `internal_only`.
- `../scripts/generate_ed301_sig_v1_vectors.py` erzeugt beide JSON-Dateien
  vollständig deterministisch neu.
- `../tests/test_ed301_sig_vectors.py` regeneriert die Pakete, vergleicht jedes
  Feld und prüft positive, negative sowie interne Fälle.

## Gemeinsame Kodierungsregeln

Die JSON-Dateien sind UTF-8, eingerückt und mit lexikographisch sortierten
Objektschlüsseln serialisiert. Bytefolgen sind kleingeschriebene
Hexadezimalzeichen ohne `0x`; die leere Bytefolge ist `""`. Bytefolgen besitzen
immer eine gerade Anzahl Hexadezimalzeichen. Große Integer stehen als
Dezimalstrings und zusätzlich als minimale Big-Endian-Hex-Magnitude in
`hex_be`. Skalare besitzen außerdem ihre normative, exakt 38 Byte lange
Little-Endian-Kodierung in `encoding_le38_hex`.

Alle Längen und Zähler, die als JSON-Wert dokumentiert werden, sind
Dezimalstrings. Dadurch hängt die Interpretation großer Werte nicht vom
Zahlenbereich eines JSON-Parsers ab.

Jedes Paket nennt die SHA-256-Digests seiner vier unmittelbaren Quellen:

1. `parameter/ed301-v1.json`,
2. `spezifikation/Ed301-Sig-v1.md`,
3. `referenz/ed301_sig.py`,
4. `referenz/ed301_curve.py`.

## Positives Schema

Das Wurzelschema heißt `Ed301-Sig-v1-positive-vectors-v1`. Jeder Eintrag unter
`vectors` besitzt:

- `inputs`: Seed, Kontext, Nachricht und Byte-Längen;
- `key_derivation`: Retry-Zähler, vollständige Frames, 64-Byte-XOF-Ausgaben,
  den geheimen Skalar `s`, Präfix, Punkt `A` und Public-Key-Kodierung;
- `nonce_derivation`: vollständigen Nonce-Frame, XOF-Ausgabe, `r`, Punkt `R`
  und `Renc`;
- `challenge_derivation`: vollständigen Challenge-Frame, XOF-Ausgabe und `k`;
- `result`: `S`, `Senc`, vollständige 76-Byte-Signatur und `verify=true`.

Punkte enthalten beide affinen Koordinaten jeweils dezimal und hexadezimal
sowie ihre komprimierte Kodierung. Der Wiederholungsvektor verweist mit
`repeat_of` auf seinen bytegleichen Ursprung.

## Negatives Schema

Das Wurzelschema heißt `Ed301-Sig-v1-negative-vectors-v1`.
`verification_vectors` enthält ausschließlich vollständige Aufrufe der Form

```text
Verify(public_key_hex, context_hex, message_length_decimal,
       message_hex, signature_hex) -> false
```

Jeder Fall hat eine stabile `id`, eine `category`, einen menschlich lesbaren
`reason` und `expected_verify=false`. Bei absichtlich abweichenden
Protokollframes dokumentiert `construction` den fremden Challenge-Frame, seine
XOF-Ausgabe und den daraus berechneten Skalar. So wird nicht bloß ein zufällig
kaputtes Byte getestet, sondern eine unter dem falschen Protokoll konsistente
Signatur.

`message_length_decimal` ist die vom Aufrufer angekündigte Länge und stimmt im
Normalfall mit der dekodierten Länge von `message_hex` überein. Die gesonderten
Längenvektoren prüfen vorzeitiges Ende, zusätzliche Bytes und einen Wert
außerhalb des `u64`-Bereichs.

`internal_only.null_and_retry` beschreibt per injizierter XOF-Ausgabe die
Sonderfälle `s=0`, `r=0`, `k=0`, `S=0` und Counter-Erschöpfung.
`internal_only.framing` vergleicht kanonische und veränderte Frames. Diese
Einträge sind ausdrücklich keine normalen Negativsignaturen: Insbesondere ist
eine abweichende Nonce-Ableitung für einen Verifizierer allein nicht
beobachtbar.

## Reproduktion und Prüfung

Aus dem Verzeichnis `ed301_technischer_abschluss`:

```sh
python3 scripts/generate_ed301_sig_v1_vectors.py
python3 tests/test_ed301_sig_vectors.py
sha256sum vektoren/ed301-sig-v1-positive.json \
  vektoren/ed301-sig-v1-negative.json
```

Der Generator verwendet nur die Python-Standardbibliothek und die lokale
Referenz. Ein abweichender Quelldigest oder irgendein abweichendes JSON-Feld
lässt das Prüfskript fehlschlagen.

---

# X301-v1-Konformitätsvektoren

## Getrennter Geltungsbereich

`x301-v1-positive.json` und `x301-v1-negative.json` gehören ausschließlich
zur rohen XDH-Funktion `X301-v1`. Sie teilen weder Schema noch Operationen mit
den vorstehenden Signaturvektoren. X301 definiert keine KDF, keinen
authentisierten Handshake und keine produktionsfreigegebene Kryptographie.

Unmittelbare Quellen und deren SHA-256-Digests stehen in beiden JSON-Dateien:

1. `spezifikation/X301-v1.md`,
2. `spezifikation/ED301-v1.md`,
3. `parameter/ed301-v1.json`,
4. `referenz/x301.py`,
5. `referenz/ed301_curve.py`.

## Positive X301-Vektoren

Das Schema `X301-v1-positive-vectors-v1` enthält zehn vollständige
Operationsvektoren. Jeder dokumentiert den rohen 38-Byte-Secret-Input, die
geklampten Bytes, `k`, die Eingabe-u-Koordinate, exakt 301 Leiteriterationen,
die projektiven Endwerte `(X,Z)`, das affine Ergebnis und sämtliche
38-Byte-Kodierungen.

Abgedeckt sind die Abschnitt-13-KATs, minimale und maximale Clamp-Grenze, zwei
gegenseitige Agreement-Paare, Hauptkurveneingaben und `u=2` auf dem expliziten
`z=2`-Twist. Jeder positive Leiterwert wird zusätzlich durch eine allgemeine
affine Montgomery-Punktmultiplikation geprüft; bei der festen Basis erfolgt
außerdem der Abgleich mit der allgemeinen Edwards-Punktmultiplikation.

`clamp_analysis` weist die 298 variablen Bitpositionen `2..299`, die sechs
ignorierten beziehungsweise überschriebenen Positionen
`0,1,300,301,302,303`, alle 64 rohen Urbilder eines gültigen Clamp-Werts und
die exakten Clamp-Grenzen nach.

## Negative und interne X301-Vektoren

Das Schema `X301-v1-negative-vectors-v1` trennt drei Klassen:

- `api_vectors` sind echte fehlschlagende `Public`, `Shared` oder `X301`
  Aufrufe. Sie decken Secret- und u-Längen, falsche Typen, mehrere Urbilder
  von `N_t`, alle reservierten u-Bits, `u=p`, `u=p+1` sowie die
  Cofaktor-Torsionswerte `u=0`, `u=1` und `u=p-1` ab. Jeder Eintrag nennt die
  genaue Ablehnungsstufe.
- `outer_parser_vectors` prüfen eine falsche Suite beziehungsweise Version
  vor dem Aufruf der rohen Funktion.
- `internal_only` enthält ausschließlich den kontrollierten KeyGen-Retry nach
  `k=N_t` und den per Fault-Injection erreichbaren All-zero-Ausgabepfad. Diese
  Fälle sind keine gewöhnlichen X301-Eingabevektoren.

`excluded_Nt_preimage_proof` listet alle 64 rohen Secret-Bytefolgen, die auf
den ausgeschlossenen Skalar `N_t` geklampt werden; vier davon erscheinen
zusätzlich als gewöhnliche API-Negativvektoren.

## X301-Reproduktion

Aus `ed301_technischer_abschluss`:

```sh
python3 scripts/generate_x301_v1_vectors.py
python3 tests/test_x301_vectors.py
sha256sum vektoren/x301-v1-positive.json \
  vektoren/x301-v1-negative.json
```

Der Generator und der Prüfer verwenden ausschließlich die
Python-Standardbibliothek und die eingefrorenen lokalen Quellen. Die JSONs
werden mit sortierten Schlüsseln, UTF-8 und abschließendem Zeilenumbruch
kanonisch regeneriert.
