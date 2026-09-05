# ED301 – technische Systemgrenze außerhalb der Possession-Engine

Stand: 12. Juli 2026

## 1. Zweck

Dieses Dokument trennt die vollständig konventionell beschreibbare
Kryptographieschicht von der spekulativen äußeren Kanal- beziehungsweise
Possession-Schicht. Es ergänzt keine Roman-Lore und macht keine Aussage
darüber, ob Retrokausalität physisch möglich ist.

Die technische Leitregel lautet:

> Alles bis einschließlich authentisierter opaker Bytefolgen wird mit
> gewöhnlicher Informatik und Kryptographie beschrieben. Die
> Possession-Engine beginnt erst hinter einer Byte-Schnittstelle und ist für
> ED301 nicht interpretierbar.

## 2. Schichten

| Schicht | Aufgabe | Status |
|---|---|---|
| `ED301-v1` | Feld, Kurve, Primuntergruppe, Basispunkt, Encodings | technisch abgeschlossen |
| `Ed301-Sig-v1` | Signatur opaker `context`- und `message`-Bytes | technisch abgeschlossen |
| `X301-v1` | rohe x-only-Diffie-Hellman-Funktion | technisch abgeschlossen und unabhängig gegengeprüft |
| Sitzungsprotokoll | KDF, Rollen, Transkript, Authentisierung, Schlüsselbestätigung | gesondertes normales Protokollprofil |
| Transportadapter | Übertragung opaker Frames mit Fehler-/Reihenfolgenbehandlung | normale Systemtechnik |
| Possession-Engine | Bedeutung, Wirkung und physikalischer Kanal | ausdrücklich außerhalb dieses Pakets |

Die Trennung ist keine Ausrede für fehlende Kryptographie: Kurve, Signatur und
rohes XDH müssen jeweils bytegenau spezifiziert und getestet sein. Sie
verhindert aber, dass ein einzelner Algorithmus fälschlich zugleich als
Handshake, Transport, Identitätssystem und physikalischer Kanal ausgegeben
wird.

## 3. Feste technische Namen und Größen

```text
Kurvenparametersatz:  ED301-v1
Signaturverfahren:    Ed301-Sig-v1
rohe XDH-Funktion:    X301-v1
Suite-Bezeichnung:    ED301-Crypto-Suite-v1
```

Die Namen sind exakte ASCII-Zeichenfolgen und dürfen nicht als Synonyme für
Ed25519, Ed448, X25519 oder X448 verwendet werden.

```text
Ed301-Sig Secret-Seed:       38 Byte
Ed301-Sig Public Key:        38 Byte
Ed301-Sig Signature:         76 Byte
X301 Raw Secret:             38 Byte
X301 Public u-coordinate:    38 Byte
X301 Raw Shared Result:      38 Byte
```

Signatur- und XDH-Schlüssel sind verschiedene Schlüsseltypen. Dieselben 38
Bytes dürfen nicht für beide Zwecke wiederverwendet werden. Auch eine
zufällige Gleichheit ihrer Bytefolgen erzeugt keine typübergreifende
Kompatibilität.

Diese Namen sind lokale Suite-Identifier, keine registrierten OIDs,
TLS-SignatureSchemes oder SupportedGroups. Ein äußeres Format muss einen
Schlüsseltyp vor der kryptographischen Operation eindeutig auswählen und
darf niemals durch versuchsweise Mehrfachinterpretation raten.

## 4. Opake Schnittstelle zur Anwendung

Der kryptographische Kern darf höchstens folgende Arten von Eingängen sehen:

- exakt typisierte Schlüsselbytes,
- einen Algorithmus- und Versions-Identifier,
- `context` als opake Bytefolge,
- `message_length` und `message` als opake Bytefolge,
- kanonische Handshake- oder Transkriptbytes eines gesonderten Profils.

Er kennt insbesondere keine Person, Erinnerung, Zeitlinie, Organisation,
Besetzung, Ankerzahl oder historische Wahrheit. Solche Inhalte können von
einer Anwendung kanonisch serialisiert und anschließend signiert werden; für
den Kryptokern bleiben sie Bytes.

Eine gültige Signatur beweist ausschließlich die Übereinstimmung von
Schlüssel, Kontext, Nachricht und Signaturgleichung. Sie beweist weder die
Semantik noch die physische Herkunft der Nachricht.

## 5. Verbindliche Anforderungen an ein Sitzungsprofil

`X301-v1` endet absichtlich beim rohen gemeinsamen u-Wert. Jedes
Sitzungsprotokoll, das diesen Wert verwendet, muss unabhängig von der
Possession-Engine mindestens Folgendes normieren:

1. **Rollen und Version:** Initiator und Responder sowie Suite und Version
   müssen eindeutig verschieden kodiert sein.
2. **Schlüsseltrennung:** Langzeit-Signaturschlüssel, statische XDH-Schlüssel,
   ephemere XDH-Schlüssel und abgeleitete Verkehrsschlüssel dürfen nicht
   verwechselt oder wiederverwendet werden.
3. **KDF:** Die 38-Byte-X301-Rohausgabe darf niemals unmittelbar als
   symmetrischer Schlüssel dienen. Eine analysierte Extract-and-Expand-KDF
   muss mindestens Suite, Version, Rollen, beide kanonischen X301-Public-Keys,
   Protokollkontext und den vollständigen Handshake-Transkriptdigest binden.
4. **Authentisierung:** Wenn Peer-Authentisierung verlangt wird, müssen
   Ed301-Sig-v1-Signaturen den kanonischen Handshake einschließlich beider
   ephemerer X301-Schlüssel, beider Rollen, Suite, Version und Nonces binden.
5. **Schlüsselbestätigung:** Das Profil muss festlegen, ob und wie beide
   Seiten den Besitz des abgeleiteten Schlüssels bestätigen.
6. **Replay-Schutz:** Frische Nonces beziehungsweise Sitzungskennungen sowie
   deren Lebensdauer und Speicherung müssen definiert sein.
7. **Record-Schutz:** Verschlüsselung benötigt ein standardisiertes AEAD,
   getrennte Richtungskeys, kollisionsfreie Nonces, Sequenznummern,
   Überlaufregeln, Rekeying und eine authentisierte Abschlussregel.
8. **Fehler:** X301-`FAIL`, Signaturfehler, unbekannte Kennungen und
   Transkriptabweichungen müssen den Handshake beenden. Ersatzschlüssel oder
   Nullwerte sind verboten.
9. **Trust:** Die Zuordnung eines Ed301-Public-Keys zu einer Person oder Rolle
   benötigt eine externe Vertrauenswurzel oder vorab bekannte Schlüssel. Sie
   entsteht nicht durch Selbstbezeichnung im Transkript.

Diese Liste ist die vollständige Kompositionsgrenze. Die Wahl etwa zwischen
einem profilierten TLS-, Noise-, SIGMA- oder eigenen sorgfältig analysierten
Handshake ist eine Systementscheidung; sie verändert ED301, Ed301-Sig-v1 und
X301-v1 nicht. Ohne eine solche Wahl darf lediglich von den drei
Kryptoprimitiven, nicht von einem vollständigen sicheren Kanal gesprochen
werden.

## 6. Transport- und Zeitrichtungsneutralität

Die Kryptographie benötigt keine monotone physikalische Zeit. Sie benötigt
lediglich wohldefinierte Bytefolgen, Rollen, Frischewerte und lokale
Zustandsregeln. Derselbe kryptographische Frame kann über Kabel, Funk,
Datenträger, Simulation oder einen hypothetischen Kanal transportiert werden.

Ein äußerer Kanal wird deshalb abstrakt als fehlerbehaftete Übertragung

```text
Send(bytes) -> möglicherweise Receive(bytes), Verlust, Duplikat oder Fehler
```

modelliert. Reihenfolge, Wiederholung und Abbruch werden vom normalen
Transport-/Sitzungsprofil behandelt. Ob `Receive` aus Sicht einer Figur
zeitlich vor `Send` liegt, ändert weder Signaturprüfung noch XDH- oder
KDF-Arithmetik.

## 7. Verhältnis zur retrokausalen Quantenkanal-Forschung

Kaiyuan Ji, Seth Lloyd und Mark M. Wilde untersuchen in
[*Retrocausal capacity of a quantum channel: Communicating through noisy
closed timelike curves*](https://arxiv.org/abs/2509.08965) die
Informationskapazität eines durch eine verrauschte postselektierte
geschlossene zeitartige Kurve modellierten Quantenkanals. Ihre Resultate
setzen ein solches Modell voraus und bestimmen darin Einmal- und asymptotische
Kapazitäten.

Für dieses Projekt ist die Arbeit eine wissenschaftliche Anleihe für die
abstrakte äußere Kanalannahme, nicht für die ED301-Kryptographie. Sie

- konstruiert keine ED301- oder X301-Operation,
- beweist nicht die physische Existenz einer verwendbaren P-CTC,
- liefert keine Possession-Mechanik,
- ersetzt weder Authentisierung noch KDF, Fehlerkorrektur oder
  Anwendungskonsistenz.

Bibliographischer Stand:

```text
Kaiyuan Ji, Seth Lloyd, Mark M. Wilde,
"Retrocausal capacity of a quantum channel:
 Communicating through noisy closed timelike curves",
arXiv:2509.08965.

v2: 15. April 2026
v3: 13. Juni 2026
Physical Review Letters 136, 230801 (2026)
arXiv-DOI: 10.48550/arXiv.2509.08965
```

Für eine datierte Romanquelle kann bewusst v2 genannt werden. Für einen
aktuellen technischen Literaturstand ist v3 beziehungsweise die
Zeitschriftenfassung anzugeben.

## 8. Aussage, die das Gesamtsystem tragen darf

Nach technischem Abschluss aller drei Primitive ist folgende Formulierung
vertretbar:

> ED301-Crypto-Suite-v1 provides a fully specified approximately 149-bit
> classical elliptic-curve parameter set, a deterministic signature scheme,
> and a strictly encoded raw XDH function. It processes opaque byte strings
> and is independent of the physical transport mechanism. A separate session
> profile is required for KDF, transcript binding, authentication and record
> protection; any retrocausal or possession mechanism remains an external
> channel assumption.

Nicht vertretbar wäre die Behauptung, ED301 erzeuge Retrokausalität, beweise
eine Zeitlinie oder mache ohne Sitzungsprofil aus einer XDH-Rohausgabe bereits
einen sicheren Kanal.
