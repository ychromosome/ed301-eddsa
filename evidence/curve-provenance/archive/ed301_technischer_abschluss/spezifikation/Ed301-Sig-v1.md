# Ed301-Sig-v1

## Sicherheitsstatus

> **NOT PRODUCTION AUDITED.** Diese Spezifikation ist bytegenau und implementierbar, wurde jedoch nicht durch einen unabhängigen externen Produktionsaudit freigegeben. Referenzcode und Testimplementierungen sind nicht automatisch seitenkanalresistent oder für den Produktiveinsatz geeignet.

Dieses Dokument definiert ausschließlich das allgemeine Signaturverfahren `Ed301-Sig-v1`. `context` und `message` sind opake Bytefolgen. Dieses Dokument definiert keine Textkodierung, Unicode-Normalisierung, strukturierte Nachrichtenbedeutung, Anwendungsprofile oder Mehrparteienprotokolle.

Die großgeschriebenen Wörter **MUSS**, **DARF NICHT**, **SOLLTE** und **DARF** bezeichnen normative Anforderungen dieses Dokuments.

## 1. Fester Verfahrensstand

`Ed301-Sig-v1` verwendet:

- die ED301-Primuntergruppe aus [`ed301-v1.json`](../parameter/ed301-v1.json),
- den dort festgelegten Basispunkt `G` exakter Ordnung `q`,
- SHAKE256 gemäß [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final),
- deterministische Nonces,
- strikte Primuntergruppenvalidierung,
- keine Clamping- oder Pruning-Regel,
- den reinen Modus `MODE = 0x00`, ohne Prehash.

Andere Versionen, Modi, Kurvenparameter, Basispunkte oder Hash-Frames sind nicht `Ed301-Sig-v1`.

Die feste äußere Schnittstelle lautet:

```text
KeyGen(seed[38]) -> (secret_key[38], public_key[38])
Sign(secret_key[38], context, message_length, message) -> signature[76] oder Fehler
Verify(public_key[38], context, message_length, message, signature[76]) -> gültig/ungültig
```

Für Version 1 gilt:

```text
0 <= len(context) <= 255
0 <= message_length <= 2^64 - 1
len(message) = message_length
```

Die Nachrichtenlänge MUSS vor dem ersten Nachrichtenbyte bekannt sein. Ein Stream unbekannter Länge ist kein gültiger Eingang dieses Modus.

## 2. Normative Kurvenparameter

Die vollständigen Feld-, Kurven-, Gruppen-, Basispunkt- und Kodierungsparameter stehen normativ in [`ed301-v1.json`](../parameter/ed301-v1.json). Implementierungen DÜRFEN keine gleichnamigen Parameter aus älteren Dokumenten übernehmen.

Die für diese Spezifikation unmittelbar benötigten Werte sind:

```text
p =
4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011

a = 2086388329
d = 301
h = 4

q =
1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403

q_hex =
800000000000000000000000000000000000016dcc80892809847fb4a312602e3a1d0be9603

ENC(G) =
6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898
```

Die Edwards-Kurve über `F_p` ist:

```text
a*x^2 + y^2 = 1 + d*x^2*y^2
```

Die Identität ist `(0, 1)`. Für den Basispunkt gilt normativ:

```text
G != Identität
[q]G = Identität
q ist prim
```

Alle Signaturrechnungen erfolgen in der von `G` erzeugten Primuntergruppe. Der Kurvencofaktor wird weder in geheime Skalare eingeklemmt noch in die Verifikationsgleichung multipliziert.

## 3. Byte- und Integerfunktionen

### 3.1 Verkettung und Längen

`X || Y` bezeichnet die unveränderte Verkettung zweier Bytefolgen.

```text
u8(n)      genau ein Byte mit 0 <= n <= 255
u32be(n)   genau vier Byte, Big Endian, 0 <= n <= 2^32-1
u64be(n)   genau acht Byte, Big Endian, 0 <= n <= 2^64-1
```

Integer-Encoder MÜSSEN bei einem Wert außerhalb ihres Bereichs fehlschlagen. Sie DÜRFEN weder abschneiden noch modulo einer Zweierpotenz reduzieren.

### 3.2 Little-Endian-Integer

Für eine Bytefolge `X = X[0] ... X[n-1]` gilt:

```text
OS2IP_LE(X) = Summe von X[i] * 256^i für i = 0 ... n-1
```

`I2OSP_LE38(x)` ist die eindeutige 38-Byte-Little-Endian-Darstellung eines Integers `0 <= x < 2^304`. Ein außerhalb dieses Bereichs liegender Wert führt zum Fehler.

### 3.3 SHAKE256

```text
H64(X) = SHAKE256(X, 64 Byte Ausgabe)
```

Jeder Aufruf beginnt mit einem frischen SHAKE256-Zustand, absorbiert exakt `X`, wird genau einmal finalisiert und liefert die ersten 64 Ausgabebytes. Zustände oder bereits ausgegebene XOF-Streams DÜRFEN nicht zwischen Operationen weiterverwendet werden.

### 3.4 Hash-to-scalar

```text
REDUCE64(X[64]) = OS2IP_LE(X) mod q
H2S(frame)      = REDUCE64(H64(frame))
```

`H2S` liefert einen Integer im Bereich `0 <= x < q`. Die Byteordnung betrifft ausschließlich die Interpretation der 64 XOF-Bytes; die SHAKE256-Bytefolge selbst wird nicht umgeordnet.

## 4. Kanonische Kodierungen

### 4.1 Feldelemente

Ein kanonisches Feldelement ist exakt 38 Byte Little Endian:

- Bits 0 bis 300 tragen den Integerwert,
- Bits 301, 302 und 303 sind null,
- der dekodierte Wert ist kleiner als `p`.

Nichtkanonische Werte werden verworfen und niemals stillschweigend modulo `p` reduziert.

### 4.2 Edwards-Punkte

`ENC(P)` ist exakt 38 Byte:

- Bits 0 bis 300 enthalten das kanonische `y`,
- Bits 301 und 302 sind null,
- Bit 303 ist das Vorzeichenbit von `x`,
- das Vorzeichen ist das niederwertigste Bit des kanonischen Repräsentanten von `x`.

Beim Dekodieren wird zunächst `y < p` geprüft. Danach wird

```text
x^2 = (1 - y^2) / (a - d*y^2) mod p
```

rekonstruiert. Ein Nullnenner, ein nichtquadratischer Wert, ein nicht auf der Kurve liegender Punkt oder ein unpassendes Vorzeichen führt zum Fehler. Bei `x = 0` ist ausschließlich Vorzeichenbit null kanonisch.

Die vollständigen Regeln und Bitpositionen in [`ed301-v1.json`](../parameter/ed301-v1.json) sind verbindlich. Für öffentliche Schlüssel und `R` gelten zusätzlich:

```text
P != Identität
[q]P = Identität
```

### 4.3 Skalare

Der Signaturskalar wird als `I2OSP_LE38(S)` kodiert. Beim Dekodieren wird die 38-Byte-Folge als Little-Endian-Integer gelesen und nur akzeptiert, wenn:

```text
0 <= S < q
```

Insbesondere ist `S = 0` kanonisch. `S >= q` wird verworfen und DARF NICHT reduziert werden. Die Bedingung `S < q` erzwingt zugleich die unbenutzten hohen Bits.

### 4.4 Äußere Formate

```text
secret_key = seed                                      # 38 Byte
public_key = ENC(A)                                    # 38 Byte
signature  = ENC(R) || I2OSP_LE38(S)                   # 76 Byte
```

Die Signatur enthält keine Suite-, Versions- oder Modusbytes. Der aufrufende Parser MUSS den Wert bereits eindeutig als `Ed301-Sig-v1`, Version 1, Modus 0 behandeln und DARF nicht versuchsweise mehrere Signaturverfahren durchprobieren.

## 5. Domain Separation und Framing

### 5.1 Feste Domain

```text
SUITE   = ASCII("Ed301-Sig-v1")
VERSION = 0x01
MODE    = 0x00

DOM = u8(12) || SUITE || VERSION || MODE
```

`DOM` ist exakt:

```text
0c45643330312d5369672d76310100
```

Die ASCII-Bytes von `SUITE` sind:

```text
45 64 33 30 31 2d 53 69 67 2d 76 31
```

### 5.2 Operationskennungen

| Wert | Name |
|---:|---|
| `0x01` | `OP_KEY_SCALAR` |
| `0x02` | `OP_NONCE_PREFIX` |
| `0x03` | `OP_NONCE` |
| `0x04` | `OP_CHALLENGE` |

### 5.3 Feldtags

| Wert | Name |
|---:|---|
| `0x01` | `TAG_SEED` |
| `0x02` | `TAG_RETRY` |
| `0x03` | `TAG_PREFIX` |
| `0x04` | `TAG_PUBLIC_KEY` |
| `0x05` | `TAG_CONTEXT` |
| `0x06` | `TAG_MESSAGE` |
| `0x07` | `TAG_COMMITMENT_R` |

### 5.4 Feldfunktion

```text
FIELD(tag, value) = u8(tag) || u64be(len(value)) || value
```

Die Längen zählen Byte. Tags, Reihenfolge, Feldanzahl und Längen sind für jeden nachfolgenden Frame fest. Es gibt keine optionalen, unbekannten, doppelten oder umgeordneten Felder.

Für feste Feldgrößen lauten die Längenpräfixe:

```text
len(seed)   = 38  -> 0000000000000026
len(prefix) = 64  -> 0000000000000040
len(Aenc)   = 38  -> 0000000000000026
len(Renc)   = 38  -> 0000000000000026
len(retry)  = 4   -> 0000000000000004
```

### 5.5 Schlüssel-Skalar-Frame

Für `0 <= i <= 2^32-1`:

```text
F_s(i) =
    DOM
    || 0x01
    || 0x02
    || FIELD(0x01, seed)
    || FIELD(0x02, u32be(i))
```

`0x01` ist die Operation und `0x02` die Feldanzahl.

### 5.6 Nonce-Präfix-Frame

```text
F_prefix =
    DOM
    || 0x02
    || 0x01
    || FIELD(0x01, seed)
```

### 5.7 Nonce-Frame

Für `0 <= i <= 2^32-1`:

```text
F_r(i) =
    DOM
    || 0x03
    || 0x05
    || FIELD(0x03, prefix)
    || FIELD(0x04, Aenc)
    || FIELD(0x05, context)
    || FIELD(0x06, message)
    || FIELD(0x02, u32be(i))
```

Der geheime Präfix, der kanonische öffentliche Schlüssel, Kontext, Nachricht und Retry-Counter sind damit gebunden.

### 5.8 Challenge-Frame

```text
F_k =
    DOM
    || 0x04
    || 0x04
    || FIELD(0x04, Aenc)
    || FIELD(0x05, context)
    || FIELD(0x06, message)
    || FIELD(0x07, Renc)
```

Die Reihenfolge `Aenc, context, message, Renc` ist normativ. Sie bindet dieselben Schnorr-Werte wie eine Reihenfolge mit vorangestelltem `R`, erlaubt aber die in Abschnitt 9 definierte Ein-Pass-Verarbeitung.

## 6. Secret-Key-Format und Schlüsselableitung

Der normative geheime Schlüssel ist ausschließlich der 38-Byte-Seed. Es gibt kein zweites normatives Format für einen expandierten Schlüssel oder einen direkt gespeicherten Skalar.

Für eine neu erzeugte Identität MUSS `seed` aus genau 38 gleichverteilten, unabhängigen Bytes eines kryptographisch sicheren Zufallszahlengenerators bestehen. Passwörter, Text, Zähler und bereits reduzierte Skalare sind keine zulässige Seed-Erzeugung.

Implementierungen DÜRFEN intern folgende Werte zwischenspeichern:

```text
seed, s, prefix, A, Aenc
```

Ein solcher Cache ist kein portables Secret-Key-Format. Vor seiner Verwendung MUSS insbesondere `A = [s]G` und `Aenc = ENC(A)` sichergestellt sein. Ein von außen gelieferter öffentlicher Schlüssel DARF bei der Signaturerzeugung nicht an die Stelle des aus dem Seed abgeleiteten `Aenc` treten.

## 7. KeyGen

Eingang: `seed`, exakt 38 Byte.

1. Bei einer anderen Seed-Länge: Fehler.
2. Setze `i = 0`.
3. Berechne `s = H2S(F_s(i))`.
4. Falls `s = 0`:
   - falls `i = 0xffffffff`: Fehler `key-scalar-retry-exhausted`;
   - andernfalls erhöhe `i` um eins und gehe zu Schritt 3.
5. Berechne `prefix = H64(F_prefix)`.
6. Berechne `A = [s]G` mit einer für geheime Skalare geeigneten Skalarmultiplikation.
7. Prüfe intern `A != Identität` und `[q]A = Identität`; andernfalls interner Fehler.
8. Setze `Aenc = ENC(A)`.
9. Gib zurück:

   ```text
   secret_key = seed
   public_key = Aenc
   ```

Für jeden akzeptierten Seed ist das Ergebnis deterministisch. Es gibt keine Clamping-Regel.

## 8. Sign

Eingänge:

```text
secret_key = seed[38]
context
message_length
message
```

### 8.1 Eingangsprüfung

1. `seed` MUSS exakt 38 Byte lang sein.
2. `len(context)` MUSS höchstens 255 sein.
3. `message_length` MUSS als `u64` darstellbar sein.
4. Die tatsächlich gelesene Nachrichtenlänge MUSS exakt `message_length` sein.
5. Kontext und Nachricht werden unverändert verarbeitet. Es findet keine Textdekodierung, Normalisierung oder Umkodierung statt.

Bei einem Verstoß wird keine Signatur ausgegeben.

### 8.2 Schlüsselwerte

Leite `s`, `prefix`, `A` und `Aenc` exakt wie in `KeyGen` ab. Ein gespeicherter Cache DARF nur verwendet werden, wenn er konsistent zum Seed ist.

### 8.3 Nonce

1. Setze `i = 0`.
2. Berechne `r = H2S(F_r(i))`.
3. Falls `r = 0`:
   - falls `i = 0xffffffff`: Fehler `nonce-retry-exhausted`;
   - andernfalls erhöhe `i` um eins und gehe zu Schritt 2.
4. Berechne `R = [r]G`.
5. Prüfe intern `R != Identität` und `[q]R = Identität`; andernfalls interner Fehler.
6. Setze `Renc = ENC(R)`.

Der Counter ist bereits beim ersten Versuch als `u32be(0)` vorhanden. Er wird nie ausgelassen und nie umgebrochen.

### 8.4 Challenge und Antwort

1. Berechne:

   ```text
   k = H2S(F_k)
   ```

2. `k = 0` ist zulässig und löst keinen Retry aus.
3. Berechne:

   ```text
   S = (r + k*s) mod q
   ```

4. `S = 0` ist zulässig und löst keinen Retry aus.
5. Setze:

   ```text
   signature = Renc || I2OSP_LE38(S)
   ```

6. Vor der Ausgabe SOLLTE die Implementierung mindestens die interne Gleichung

   ```text
   [S]G = R + [k]A
   ```

   erneut prüfen und bei einer Abweichung mit internem Fehler abbrechen.

Die Signatur ist exakt 76 Byte. Derselbe Seed, Kontext und dieselbe Nachricht ergeben stets dieselbe Signatur.

## 9. Normative Streaming-Reihenfolge

Ein korrektes gepuffertes Verfahren darf die vollständigen Frames aus Abschnitt 5 direkt bilden. Für große Nachrichten ist folgende Ein-Pass-Verarbeitung normativ äquivalent und wird empfohlen:

1. Prüfe `message_length` vor dem ersten Nachrichtenbyte.
2. Initialisiere einen geheimen SHAKE256-Zustand `state_r` und absorbiere den Anfang von `F_r(i)` bis einschließlich

   ```text
   TAG_MESSAGE || u64be(message_length)
   ```

   Der Counter wird noch nicht absorbiert.
3. Initialisiere einen getrennten SHAKE256-Zustand `state_k` und absorbiere den Anfang von `F_k` bis einschließlich

   ```text
   TAG_MESSAGE || u64be(message_length)
   ```

   `Renc` wird noch nicht absorbiert.
4. Lies die Nachricht genau einmal. Absorbiere jedes Chunk unverändert und in derselben Reihenfolge in `state_r` und `state_k`.
5. Bei vorzeitigem Ende, zusätzlichen Bytes oder einer Längenänderung: Fehler.
6. Sichere beziehungsweise kopiere den noch nicht finalisierten `state_r` nach dem letzten Nachrichtenbyte.
7. Für jeden Nonce-Versuch kopiere diesen Zustand, absorbiere

   ```text
   FIELD(TAG_RETRY, u32be(i))
   ```

   finalisiere die Kopie, entnimm 64 Byte und reduziere modulo `q`.
8. Sobald `r != 0` ist, berechne `Renc`.
9. Absorbiere

   ```text
   FIELD(TAG_COMMITMENT_R, Renc)
   ```

   in `state_k`, finalisiere ihn, entnimm 64 Byte und reduziere modulo `q`.

Damit gehen exakt dieselben Nachrichtenbytes in Nonce und Challenge ein. Ein Implementierungsmodell, das Kontext oder Nachricht zwischen zwei Durchläufen verändern lässt, ist unzulässig. Eine Implementierung ohne kopierbaren SHAKE-Zustand DARF puffern oder aus einer nachweislich unveränderlichen Quelle erneut lesen; die resultierenden Frames MÜSSEN bytegleich sein.

Die Feldreihenfolge darf nicht für eine vermeintliche Streaming-Optimierung verändert werden.

## 10. Verify

Eingänge:

```text
public_key = Aenc
context
message_length
message
signature
```

Die Verifikation führt die folgenden Schritte in dieser Reihenfolge aus:

1. Falls `len(Aenc) != 38`: ungültig.
2. Falls `len(signature) != 76`: ungültig.
3. Falls `len(context) > 255`: ungültig.
4. Falls `message_length` nicht als `u64` darstellbar ist: ungültig.
5. Teile die Signatur exakt auf:

   ```text
   Renc  = signature[0..37]
   Senc  = signature[38..75]
   ```

6. Dekodiere `Aenc` streng nach Abschnitt 4.2. Bei einem Fehler: ungültig.
7. Dekodiere `Renc` streng nach Abschnitt 4.2. Bei einem Fehler: ungültig.
8. Prüfe:

   ```text
   A != Identität
   R != Identität
   [q]A = Identität
   [q]R = Identität
   ```

   Bei einem Fehlschlag: ungültig.
9. Setze `S = OS2IP_LE(Senc)`. Falls `S >= q`: ungültig. Es erfolgt keine Reduktion. `S = 0` bleibt zulässig.
10. Lies exakt `message_length` Nachrichtenbytes und bilde `F_k` mit den geprüften, kanonischen Eingabebytes `Aenc` und `Renc`. Bei abweichender tatsächlicher Länge: ungültig.
11. Berechne `k = H2S(F_k)`. `k = 0` bleibt zulässig.
12. Akzeptiere genau dann, wenn:

    ```text
    [S]G = R + [k]A
    ```

13. Andernfalls: ungültig.

Es wird keine cofactor-multiplizierte Gleichung verwendet. Ein Verifizierer DARF Fehler intern unterscheiden, SOLLTE gegenüber nicht vertrauenswürdigen Aufrufern aber nur das Gesamtergebnis `gültig` oder `ungültig` offenlegen.

## 11. Vollständige Fehler- und Ablehnungsregeln

### 11.1 KeyGen und Sign

KeyGen beziehungsweise Sign MÜSSEN ohne Ausgabe eines Schlüssels oder einer Signatur fehlschlagen bei:

- Seed-Länge ungleich 38,
- Kontextlänge größer als 255,
- nicht als `u64` darstellbarer Nachrichtenlänge,
- unbekannter Nachrichtenlänge,
- tatsächlicher Nachrichtenlänge ungleich dem angekündigten Wert,
- Überlauf eines `u32`-Retry-Counters,
- inkonsistentem Secret-Key-Cache,
- interner Punkt-, Skalar-, SHAKE- oder Gleichungsprüfung mit fehlerhaftem Ergebnis.

### 11.2 Verify

Verify MUSS ablehnen bei:

- falscher öffentlicher Schlüssellänge,
- falscher Signaturlänge,
- zu langem Kontext,
- ungültiger oder inkonsistenter Nachrichtenlänge,
- reservierten Punktbits,
- `y >= p`,
- nicht rekonstruierbarem oder nicht auf der Kurve liegendem Punkt,
- unkanonischem Vorzeichen bei `x = 0`,
- Identität als `A` oder `R`,
- Kleinordnungs- oder Mixed-Order-Punkt,
- Punkt außerhalb der `q`-Untergruppe,
- `S >= q`,
- abweichendem Kontext oder abweichender Nachricht,
- abweichender Suite-, Versions-, Modus-, Operations- oder Framingdefinition,
- nicht erfüllter Signaturgleichung.

Kein Decoder darf einen nichtkanonischen Wert reduzieren, maskieren, normalisieren oder in eine kanonische Darstellung umschreiben und anschließend akzeptieren.

## 12. Nullfälle und Retry-Semantik

| Wert | Normative Behandlung |
|---|---|
| `s = 0` | deterministischer Retry mit nächstem `u32be`-Counter |
| `r = 0` | deterministischer Retry mit nächstem `u32be`-Counter |
| `k = 0` | akzeptieren, kein Retry |
| `S = 0` | kanonisch kodieren beziehungsweise dekodieren; Gleichung entscheidet |

Der Retry-Counter ist durch Suite, Version, Modus, Operation, Tag und feste Länge domänensepariert. Ein erster Versuch ohne Counterfeld ist verboten.

Testimplementierungen MÜSSEN die vier Fälle durch injizierte XOF-Ausgaben erreichen können. Solche Injektionen gehören ausschließlich in Tests und dürfen in einer produktiven API nicht verfügbar sein.

## 13. Bias der Skalarreduktion

Für einen ideal gleichverteilten 64-Byte-XOF-Wert sei:

```text
M = 2^512 = m*q + u
```

Für den normativen Wert von `q` gilt exakt:

```text
m =
13164036458569648337239753460458804039861886918478992895373057760

u =
74959542985490799352961604733020823608148565522845560802637567942191364016481119731966816
```

Bei direkter Reduktion modulo `q` treten `u` Reste jeweils `m+1` Mal und `q-u` Reste jeweils `m` Mal auf. Der exakte Total-Variation-Abstand zur Gleichverteilung auf `Z_q` ist:

```text
delta = u*(q-u) / (q*2^512)
      = 5.179278358612594991745055173689035925787543042476799209147064945648867831447738725897321070817039... * 10^-66
      = 2^(-216.8745031648428156949321453233371198267329503043585110773577984834442387916...)
```

Insbesondere gilt:

```text
delta < 2^-215
```

Die Wahrscheinlichkeit `s = 0`, `r = 0` oder `k = 0` in einem einzelnen Versuch ist:

```text
(m+1) / 2^512
= 9.8181869305954531061915439099725512859504310200841166051097431028091356577... * 10^-91
```

Der Retry für `s` und `r` erzeugt die entsprechende Verteilung bedingt auf einen Nichtnullwert. Ihr Total-Variation-Abstand zur Gleichverteilung auf `{1, ..., q-1}` ist ebenfalls ungefähr `2^-216.874503...`. Diese Abweichung liegt deutlich unter dem generischen Sicherheitsniveau der etwa 299-Bit-Primordnung. Rejection Sampling ist nicht Teil dieses Verfahrens.

## 14. Sicherheitsannahmen und Grenzen

### 14.1 Grundannahmen

Die Signatursicherheit beruht auf:

- der Schwierigkeit des diskreten Logarithmus in der Primuntergruppe der Ordnung `q`,
- der Pseudorandomness beziehungsweise Random-Oracle-Modellierung der getrennten SHAKE256-Aufrufe,
- einem geheimen, gleichverteilten 38-Byte-Seed,
- korrekter, strikter Punkt- und Skalarkodierung,
- einer korrekten und gegen relevante Seitenkanäle gehärteten Implementierung.

Der Aufbau folgt dem bekannten EdDSA-/Schnorr-Kern aus [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), verwendet aber die in diesem Dokument vollständig eigene Kurve, Untergruppe, Kodierung und Hash-Domain.

### 14.2 Key Prefixing und Schlüsselersetzung

Der Challenge-Hash bindet `Aenc`. Damit ist die öffentliche Schlüsselkodierung Teil jeder Challenge und der klassische additive Related-Key-Angriff gegen nicht key-prefixed Schnorr-Signaturen wird vermieden. Die Nonce-Ableitung bindet `Aenc` zusätzlich, damit eine fehlerhafte oder manipulierte Berechnung des öffentlichen Schlüssels nicht unbemerkt zu einer gefährlichen Nonce-Wiederverwendung führt. Diese beiden Konstruktionsgründe entsprechen den Sicherheitsüberlegungen von [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

Strikte kanonische Dekodierung verhindert, dass derselbe mathematische Schlüssel unter mehreren Bytefolgen in die Hash-Domain eingeht.

### 14.3 Cross-Protocol-Trennung

Suite, Version, Modus und Operation sind in jedem Hash-Frame enthalten. Verschiedene Operationen verwenden frische SHAKE256-Zustände. Seed und Nonce-Präfix DÜRFEN nicht als geheime Eingaben eines anderen Signaturverfahrens wiederverwendet werden.

Da die 76-Byte-Signatur keinen Algorithmusbezeichner enthält, muss die aufrufende Anwendung das Signaturverfahren eindeutig auswählen. Algorithmus-Fallback nach dem Muster „prüfe mehrere Verfahren bis eines akzeptiert“ ist verboten.

Ein Anwendungsprotokoll, das zusätzliche Algorithmus-, Rollen- oder Versionskennungen benötigt, muss diese als Teil seines opaken Kontextes oder seiner opaken Nachricht binden. Dieses Dokument legt solche Werte nicht fest.

### 14.4 Malleabilität

`S < q`, eine feste 38-Byte-Skalarkodierung, kanonische Punktkodierungen, Identitätsausschluss und strikte Primuntergruppenprüfung verhindern die bekannten Encoding-, Skalar- und Cofactor-Malleabilitäten. Insbesondere darf kein Vielfaches von `q` zu `S` addiert werden. Die Bedeutung der `S < q`-Prüfung entspricht der Malleabilitätsbetrachtung in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).

Dieses Dokument behauptet ohne gesonderten formalen Beweis keine konkrete starke Unfälschbarkeitseigenschaft über die beschriebenen strukturellen Regeln hinaus.

### 14.5 Deterministische Nonces

Deterministische Nonces vermeiden eine Abhängigkeit von Signaturzeit-Zufall. Sie machen Signaturen reproduzierbar, aber nicht unempfindlich gegen Implementierungsfehler.

Werden dasselbe `r` und verschiedene Challenges verwendet, kann der geheime Skalar aus den beiden Signaturgleichungen berechnet werden. Daher gelten zwingend:

- `prefix` ist genauso geheim wie `s` und `seed`,
- Nonce- und Challenge-Domain dürfen nicht verwechselt werden,
- `Aenc`, Kontext und Nachricht müssen in der Nonce gebunden bleiben,
- dieselben Nachrichtenbytes müssen in Nonce und Challenge eingehen,
- eine fehlerhafte Wiederverwendung oder ein Fault im Nonce-Pfad ist als Schlüsselkompromittierung zu behandeln.

Zusätzliche Zufallsbytes oder Hedging sind nicht Bestandteil von Modus 0 und dürfen nicht stillschweigend ergänzt werden. Ein solches Verfahren wäre ein anderer Modus mit eigener Domain und eigenen Testvektoren.

### 14.6 Proof of Possession und Mehrparteienverfahren

Eine gültige Einzelunterschrift beweist nicht, dass eine außerhalb dieses Verfahrens auftretende Person, Registrierung oder Rollenbehauptung korrekt an den Schlüssel gebunden wurde. Falls eine Schlüsselregistrierung einen Proof of Possession verlangt, muss das aufrufende Protokoll eine eigene, gegen Replay geschützte Registrierungsnachricht unter einem festen Anwendungskontext signieren.

`Ed301-Sig-v1` definiert keine Schlüsselaggregation, Multi-Signatur und keine Threshold-Signatur. Key Prefixing im Einzelverfahren ersetzt weder Rogue-Key-Schutz noch Teilnehmerbindung eines Mehrparteienprotokolls. Deterministische Einzel-Signer-Nonces dürfen nicht unverändert in einem solchen Protokoll eingesetzt werden. Ein Mehrparteienverfahren benötigt eine eigene analysierte Spezifikation, wie dies beispielsweise für Schnorr-Threshold-Signaturen in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) geschieht.

### 14.7 Seitenkanäle, Speicher und Faults

Produktionsimplementierungen MÜSSEN mindestens:

- Feld- und Skalararithmetik für geheime Werte ohne geheimnisabhängige Speicherzugriffe und Verzweigungen implementieren,
- die Basispunktmultiplikationen mit `s` und `r` seitenkanalresistent ausführen,
- Seed, `s`, Prefix, `r` und geheime SHAKE-Zustände als Schlüsselmaterial behandeln,
- geheime Zwischenwerte nach Gebrauch bestmöglich löschen,
- Speicherüberläufe beim Verarbeiten von `u64`-Längen verhindern,
- Nachrichtenpuffer während der Signatur unveränderlich halten,
- Fehler in Skalarmultiplikation, Cache oder finaler Gleichung erkennen und ohne Signaturausgabe abbrechen.

Die Offenlegung von `prefix` erlaubt regelmäßig, `r` für eine bekannte Signatur zu rekonstruieren und daraus bei `k != 0` den geheimen Skalar zu bestimmen. Ein Prefix-Leak ist deshalb als vollständige Kompromittierung des Signaturschlüssels zu behandeln.

Die allgemeinen Seitenkanalhinweise für EdDSA in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) gelten sinngemäß; dieses Dokument bescheinigt keiner Implementierung deren Einhaltung.

## 15. Konformität

Eine Implementierung ist nur dann konform, wenn sie:

- exakt die Parameter aus `ed301-v1.json` verwendet,
- sämtliche Frames aus Abschnitt 5 bytegleich erzeugt,
- für alle Hash-to-scalar-Aufrufe genau 64 SHAKE256-Ausgabebytes verwendet,
- Little Endian ausschließlich an den festgelegten Integerstellen und Big Endian ausschließlich für Längen und Counter verwendet,
- die Null- und Retry-Regeln aus Abschnitt 12 umsetzt,
- alle strikten Ablehnungsfälle aus Abschnitt 11 umsetzt,
- gepufferte und gestreamte Verarbeitung auf identischen Bytefolgen zum identischen Ergebnis führt,
- keine Prehash-, Clamping-, Cofactor-Verifikations- oder Zufalls-Hedging-Regel hinzufügt,
- positive und negative Testvektoren einschließlich injizierter Nullfälle reproduziert.

Mindestens zu testen sind:

- leerer und 255-Byte-Kontext sowie Ablehnung von 256 Byte,
- leere, kurze und gestreamte lange Nachrichten,
- exakte `u64be`-Längenframes einschließlich synthetischer Grenzlängen,
- Retry-Counter `0` und `1`,
- injiziertes `s=0`, `r=0`, `k=0` und `S=0`,
- vertauschte Tags, Feldreihenfolgen und Byteordnungen,
- falsche Suite, Version, Modus und Operation,
- nichtkanonisches `A`, `R` und `S`,
- Identitäts-, Kleinordnungs- und Mixed-Order-Punkte,
- inkonsistenter Cache aus Seed, Skalar und öffentlichem Schlüssel,
- Gleichheit der gepufferten und der Ein-Pass-Signatur.

## 16. Primärreferenzen

- [NIST FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://csrc.nist.gov/pubs/fips/202/final)
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032.html)
- [BIP 340 — Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [RFC 9591 — The Flexible Round-Optimized Schnorr Threshold Protocol](https://www.rfc-editor.org/rfc/rfc9591.html)
