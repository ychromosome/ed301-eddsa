# ED301-Whitepaper 1.2 – technische Änderungsliste zu Version 1.1

Stand: 12. Juli 2026  
Gegenstand: ausschließlich Kurvenmathematik, Kodierungen, `X301-v1`,
`Ed301-Sig-v1`, Interoperabilitätsnachweise und Sicherheitsgrenzen

## 1. Zweck, Quellenstand und Abgrenzung

Dieses Dokument ist eine präzise Arbeitsanweisung für eine spätere
Whitepaper-Version 1.2. Es ist **keine** umgeschriebene Whitepaper-Fassung.
Das Ausgangs-PDF
[ED301 Whitepaper v1.1](../../ED301_Whitepaper_Retrocausal_Compatibility_Edition_v1_1.pdf)
wird nicht verändert.

Verwendet wurden ausschließlich die drei freigegebenen technischen
Eingangsquellen:

1. [ED301 Whitepaper v1.1](../../ED301_Whitepaper_Retrocausal_Compatibility_Edition_v1_1.pdf),
   SHA-256
   `bbb1dceb92210b042d62ad0b1cc1371b199dcb3272b9a4bf7066e31cad3c20b5`;
2. [Mathematische Empfehlungen](../../EMPFEHLUNGEN_ED301_WHITEPAPER_MATHEMATIK.md),
   SHA-256
   `dbfcd3d3b0f0b16c3d1e3b674098770e157a205a1a6ed81e5ddb16b40a922d25`;
3. [Technisches Arbeitsbriefing](../../BRIEFING_CODEX_ED301_KURVE_UND_SIGNATUR.md),
   SHA-256
   `48289acd2044c3743e5f80899018466c269b19217ee28aea09973502d36cef83`.

Hinzu kommen ausschließlich die fertiggestellten Rechen-, Spezifikations-
und Gegenprüfungsartefakte unter `ed301_technischer_abschluss/`. Es wurden
keine Lore-Dateien ausgewertet.

Die Seitenangaben beziehen sich auf die im PDF gedruckten Seitenzahlen
`1..6`. Nichttechnische Aussagen und die erzählerische Ausgestaltung der
Abschnitte 1 und 4 werden hier nicht redigiert. Wo dort kryptographische
Fähigkeiten behauptet werden, nennt diese Liste nur die technisch notwendige
Korrektur.

## 2. Gesamtentscheidung für Version 1.2

Version 1.2 ist kein bloßes Erratum. Sie normiert einen anderen
twisted-Edwards-Parameter und ist deshalb kryptographisch inkompatibel zu dem
Entwurf aus Version 1.1:

| Gegenstand | Whitepaper 1.1 | zwingender Stand für 1.2 |
|---|---|---|
| Feld | `p = 2^301 - 2^99 + 947` | unverändert, formal prim bewiesen |
| Edwards-Parameter | `a=1`, `d=301` | `a=2086388329=45677^2`, `d=301` |
| Hauptgruppenstruktur | unbekannt, `h=4` nur erwartet | exakt `N=4q`, `q` prim |
| Twiststruktur | nicht bestimmt | expliziter Twist mit exakt `N_t=4q_t`, `q_t` prim |
| Sicherheitsangabe | ungefähr 150 Bit als Zielbehauptung | ungefähr 150 Bit, genauer 149,826 beziehungsweise konservativ 149,326 Bit |
| Cofactor-Regel | vorläufig `[8]` | Edwards-Clearing `[4]`; Signaturen strikt in der `q`-Untergruppe |
| Montgomery-Leiter | Plus-Konstante ohne vollständige passende Leiter | RFC-7748-Form mit `A24_minus` und vollständigem Pseudocode |
| Signatur | unspezifizierte „ED301 signatures“ | getrenntes, bytegenaues `Ed301-Sig-v1` |
| X301 | als fertiges XDH/KEX dargestellt, aber unvollständig | bytegenaues `X301-v1` als rohe XDH-Funktion; keine KDF und kein authentisierter Handshake |
| X301-Secret-Sicherheit | aus der Feldgröße abgeleitet | 298 variable Clamp-Bits; ungefähr `2^149` generischer Exponentensuchaufwand |
| Produktionsstatus | Draft-Hinweis | technisch geprüft, aber ausdrücklich nicht produktionsfreigegeben |

Die Bezeichnung `ED301-v1` MUSS in der technischen Fassung ausschließlich den
Parametersatz mit `c=44730` bezeichnen. Die alte `a=1`-Kurve DARF nur als
historisch negativer Ausgangskandidat erscheinen, etwa unter der eindeutigen
Bezeichnung `ED301-draft-a1`.

## 3. Konkrete Änderungen nach PDF-Seite und Abschnitt

Die Aktionswörter **ERSETZEN**, **STREICHEN** und **NEU EINFÜGEN** sind
verbindlich für die technische Konsistenz von Version 1.2.

### 3.1 Seite 1 – Titelblatt und Revisionsstatus

- **Fundstelle:** Versionsfeld `1.1` und Revisionsfokus.
- **ERSETZEN:** Version durch `1.2`; Revisionsfokus technisch mindestens als
  „Audited ED301 curve parameters and Ed301-Sig-v1“ kennzeichnen.
- **NEU EINFÜGEN:** gut sichtbarer Status:
  `TECHNICALLY AUDITED, NOT PRODUCTION STANDARDIZED`.
- **Grund:** Die Parameter, Signatur und Vektoren sind intern abgeschlossen;
  eine externe Produktionsfreigabe liegt nicht vor.

### 3.2 Seite 2 – Abstract

- **Fundstelle:** „A birational Montgomery equivalent, X301, is provided for
  X-coordinate Diffie-Hellman key exchange.“
- **ERSETZEN:** `X301-v1` ist eine bytegenaue rohe XDH-Funktion mit
  38-Byte-Secret, strikter 38-Byte-u-Kodierung und verpflichtender
  Null-/Unendlich-Ablehnung. Sie liefert rohes gemeinsames Material, aber
  weder KDF noch Authentisierung oder einen vollständigen sicheren Kanal.
- **STREICHEN:** jede Aussage, wonach allein das Vorhandensein des
  Montgomery-Modells oder ein erfolgreicher `Shared`-Aufruf bereits einen
  fertigen Sitzungsschlüssel oder sicheren Handshake bereitstellt.
- **Fundstelle:** allgemeine Aussage „robust classical cryptographic
  properties“.
- **ERSETZEN:** mathematisch geprüfte Parameter mit ungefähr 150 Bit
  generischer klassischer Sicherheit, verbunden mit dem ausdrücklichen
  Hinweis auf die neue projektspezifische Kurve und fehlende
  Produktionsfreigabe.

### 3.3 Seite 2 – Abschnitt 1 „Motivation and Symbolism“

- **NEU EINFÜGEN:** ein einziger technischer Trennsatz: Die Zahlen `301`,
  `99` und `947` begründen die transparente Parameterherkunft, aber keine
  Sicherheitsgarantie und keine Protokollkapazität.
- **Keine weitere Änderung:** Die vorhandenen Zahlenwerte werden technisch
  nicht beanstandet; ihre nichttechnische Bedeutung ist nicht Gegenstand
  dieser Liste.

### 3.4 Seite 2 – Abschnitt 2 „Curve Definition“

- **Fundstelle:** „The twisted Edwards form is defined with a = 1 and d =
  301“ und die Gleichung `x^2+y^2=1+301*x^2*y^2`.
- **ERSETZEN:** durch die in Abschnitt 6.1 dieser Liste angegebene Kurve mit
  `a=2086388329` und `d=301`.
- **NEU EINFÜGEN:** einen historischen Auditabschnitt über den negativen
  `a=1`-Befund gemäß Abschnitt 5 dieser Liste.
- **NEU EINFÜGEN:** die transparente Auswahlregel
  `s=947+c`, `a=s^2 mod p`, kleinster bestandener Zähler `c=44730`.
- **Fundstelle:** Eigenschaft „a = 1 is a quadratic residue“.
- **ERSETZEN:** `a=45677^2` ist Quadrat, `d=301` ist Nichtquadrat;
  `a,d != 0` und `a != d`.
- **Fundstelle:** „complete Edwards addition in constant time“.
- **ERSETZEN:** Die vollständige Additionsformel ist mathematisch für alle
  rationalen Punktpaare definiert. Konstante Laufzeit ist eine Eigenschaft
  einer konkreten Implementierung und wird durch die Kurvenform nicht allein
  garantiert.
- **NEU EINFÜGEN:** vollständige Addition, Identität, Negation sowie Punkte
  der Ordnung zwei und vier aus der
  [normativen Kurvenspezifikation](../spezifikation/ED301-v1.md).
- **Fundstelle:** „The field modulus is prime; the primality certificate is
  retained in an internal annex.“
- **ERSETZEN:** eindeutiger Verweis auf das tatsächlich vorliegende
  [ECPP-Zertifikat](../zertifikate/p_ecpp_internal.pari), seine
  [menschenlesbare Fassung](../zertifikate/p_ecpp_human.txt) und den
  [Reproduktionslauf](../rohresultate/audit_c44730_full_reproducibility_pari.txt).

### 3.5 Seite 2 – Unterabschnitt „Montgomery equivalent: X301“

- **Fundstelle:** Formeln mit `a=1` und die daraus berechneten alten Werte
  für `A`, `B` und `A24`.
- **ERSETZEN:** sämtliche Montgomery-Konstanten durch Abschnitt 6.3 dieser
  Liste.
- **UMBENENNEN:** Überschrift in „X301-v1 Raw XDH Function“ oder eine
  inhaltlich gleich eindeutige Form.
- **Fundstelle:** `A24 = (A+2)/4` ohne zugehörige vollständige
  Verdopplungsformel.
- **ERSETZEN:** normative Minus-Konvention
  `A24_minus=(A-2)/4` zusammen mit
  `z2=E*(AA+A24_minus*E)` und der vollständigen Leiter aus
  [ED301-v1](../spezifikation/ED301-v1.md).
- **STREICHEN:** die Plus-Konstante als normative Leiterkonstante. Sie DARF
  nur als nichtnormativer Vergleichswert erscheinen und niemals mit der
  Minus-Formel vermischt werden.
- **NEU EINFÜGEN:** normative Verknüpfung zur
  [X301-v1-Spezifikation](../spezifikation/X301-v1.md): 38-Byte-Secret,
  38-Byte-u, Clamping, Sonderablehnung `k=N_t`, feste Basis-u,
  `KeyGen/Public/Shared`, 301 Leiteriterationen und sämtliche Fehlerfälle.

### 3.6 Seiten 2–3 – Abschnitt 3 „Cryptographic Properties“

- **Fundstelle:** „Curve parameters: a = 1, d = 301“.
- **ERSETZEN:** `a=2086388329`, `d=301`.
- **Fundstelle:** „Cofactor: expected h = 4; exact group order and twist
  order remain to be audited“.
- **ERSETZEN:** exakte Ordnungen, Primfaktoren und Cofaktoren aus Abschnitt
  6.2 dieser Liste; das Wort `expected` und der Auditvorbehalt entfallen.
- **Fundstelle:** „Security target: approximately 150-bit classical ECDLP
  security“.
- **ERSETZEN:** die genaue und begrenzte Formulierung aus Abschnitt 7.
- **Fundstelle:** „scalars are clamped to multiples of 8“ und Clearing mit
  `[8]`.
- **STREICHEN:** vollständig aus dem ED301- und Signaturkern.
- **ERSETZEN:** allgemeines Edwards-Cofactor-Clearing ist `[4]P`; öffentliche
  Signaturpunkte werden nicht gecleart, sondern kanonisch dekodiert, die
  Identität wird verworfen und `[q]P=O` wird geprüft. Davon getrennt legt
  `X301-v1` sein eigenes Clamping fest: Bits `0,1,301,302,303` löschen, Bit
  `300` setzen und den einzigen annihilierenden Clamp-Wert `k=N_t` ablehnen.
- **Fundstelle:** „The Montgomery equivalent X301 supports ladder-based XDH“.
- **ERSETZEN:** `X301-v1` definiert die rohe x-only-XDH-Funktion vollständig.
  Ihre erfolgreiche Ausgabe ist noch kein KDF-Ergebnis, authentisierter
  Handshake oder sicherer Kanal.
- **NEU EINFÜGEN:** X301-v1 besitzt genau 298 variable Clamp-Bits und damit
  ungefähr `2^149` generischen privaten Exponentensuchaufwand. Diese Grenze
  ist getrennt von der 149,826/149,326-Bit-Bewertung der vollen Kurvengruppe
  auszuweisen.
- **Fundstelle:** Elligator-2-Kompatibilität als bedingte Aussage.
- **VERSCHIEBEN:** in einen klar als separates Zukunftsprofil bezeichneten
  Abschnitt. ED301-v1 definiert kein Elligator- oder Hash-to-curve-Profil.

### 3.7 Seite 3 – Abschnitt 4 „Use Case“

- **Fundstelle:** Aussagen wie „ED301 authenticates“ und „establishes session
  keys via X301“.
- **ERSETZEN:** Die Kurve selbst authentisiert nichts. Das getrennte
  `Ed301-Sig-v1` authentisiert opake Bytefolgen unter einem öffentlichen
  Schlüssel. `X301-v1` erzeugt ein rohes gemeinsames u-Ergebnis; erst ein
  gesondertes Protokoll mit KDF, Rollen-/Transkriptbindung und gegebenenfalls
  Authentisierung darf daraus Sitzungsschlüssel oder einen sicheren Kanal
  ableiten.
- **Keine weitere Änderung:** Anwendungsspezifische Begriffe oder Abläufe
  werden durch diese technische Liste nicht umgestaltet.

### 3.8 Seite 3 – Abschnitt 4.1

- **Fundstelle:** „ED301 continues to provide a large prime-order group“.
- **ERSETZEN:** Präzise ist `E(F_p)` eine zyklische Gruppe der Ordnung `4q`;
  der festgelegte Basispunkt `G` erzeugt die Primuntergruppe der Ordnung `q`.
- **NEU EINFÜGEN:** Der mathematische Cofaktor `4` ist keine Ursache und kein
  Beweis für eine anwendungsseitige Vierergrenze.
- **Keine weitere Änderung:** Die Anwendungspolitik selbst ist außerhalb des
  technischen Abschlusses.

### 3.9 Seiten 3–5 – Abschnitt 4.2

Nur folgende kryptographische Aussagen sind zu ändern; Struktur und Semantik
des Anwendungsprotokolls werden hier nicht neu festgelegt:

- **Fundstelle:** „ED301 provides identity binding“, „rejection of
  contradictory ... states“ und ähnliche Fähigkeitszuweisungen.
- **ERSETZEN:** `Ed301-Sig-v1` kann belegen, dass eine kanonische Bytefolge
  unter einem bestimmten öffentlichen Schlüssel signiert wurde. Es beweist
  weder Identitätssemantik noch zeitliche oder inhaltliche Widerspruchsfreiheit.
  Solche Entscheidungen müssen einem externen Anwendungsmodul zugeschrieben
  werden.
- **Fundstelle:** Felder `ed301_past_signature` und
  `ed301_future_signature`, ferner „All ED301 signatures verify“.
- **ERSETZEN:** Algorithmusbezug durch `Ed301-Sig-v1`; `context` und
  `message` sind aus Sicht des Signaturkerns opake Bytefolgen. Eine
  anwendungsspezifische kanonische Serialisierung ist nicht Teil von
  `Ed301-Sig-v1` und darf nicht durch einen unbestimmten Hash `H(...)`
  vorgetäuscht werden.
- **STREICHEN:** jede Implikation, eine erfolgreiche Signaturprüfung beweise
  physische, semantische oder historische Aussagen.
- **KENNZEICHNEN:** Ein weiterhin dargestelltes Transcript-, Trust- oder
  Kapazitätsprofil ist ein separates Anwendungsprofil und kein Bestandteil
  von ED301-v1 oder Ed301-Sig-v1.

### 3.10 Seite 5 – Abschnitt 5 „Implementation Notes“

- **Fundstelle:** „Until |E(F_p)| = h*q is audited, assume h = 4“.
- **ERSETZEN:** `N=4q` und `N_t=4q_t` sind exakt bewiesen. Kein provisorischer
  Cofaktor und kein Decaf-Platzhalter bleiben bestehen.
- **Fundstelle:** bisherige drei Encoding-Stichpunkte.
- **ERSETZEN:** bitgenaue Feld-, Edwards-Punkt- und Skalarkodierungen aus
  Abschnitt 6.5 dieser Liste. Für Signaturschlüssel und `R` kommt strikte
  Primuntergruppenprüfung hinzu.
- **Fundstelle:** „X301 u-coordinate: ... reject all-zero shared secrets“.
- **ERSETZEN:** `X301-v1` verlangt exakt 38 Byte, Bits `301..303` null und
  `u<p`; anders als tolerante RFC-7748-Eingaben werden Werte weder maskiert
  noch modulo `p` reduziert. `Z=0` und eine 38-Byte-Nullausgabe sind zwingend
  `FAIL`. Die erfolgreiche Rohausgabe DARF dennoch nicht unmittelbar als
  symmetrischer Schlüssel verwendet werden.
- **Fundstelle:** „Elligator mappings may be applied ... if required“.
- **STREICHEN:** aus den Implementierungsanweisungen. Ohne eigene Suite,
  Mapping-, Domain-, Ausnahme- und Testregeln ist dies keine implementierbare
  Anweisung.

### 3.11 Seite 5 – Abschnitt 6 „Caveats and Future Work“

- **STREICHEN als erledigt:** Kurven- und Twistordnung berechnen,
  ECPP-Zertifikat speichern, Basispunkt und Testvektoren erst nach
  Gruppenabschluss veröffentlichen.
- **ERSETZEN:** durch Verweise auf die vorhandenen Zertifikate,
  Spezifikationen, Vektoren und die unabhängige Gegenimplementierung.
- **STREICHEN als erledigt:** die Spezifikation einer rohen X301-Funktion,
  ihres Clampings, ihrer u-Kodierung und ihrer positiven wie negativen
  Testvektoren.
- **BEIBEHALTEN ausschließlich als separate Profile:** Elligator, ein auf
  X301-v1 aufbauender KDF-/Handshake-Entwurf, ein mögliches
  Post-Quantum-Hybridprofil und anwendungsspezifische Serialisierungen.
- **NEU EINFÜGEN als reale Restarbeit:** externer Kryptoaudit,
  konstantzeitliche Produktionsimplementierung, Seitenkanal- und Fault-Tests,
  sichere Integration und Schlüsselverwaltung.

### 3.12 Seiten 5–6 – Appendix A „Quick Verification Facts“

- **BEIBEHALTEN:** `p mod 4 = 3`, `d=301` ist Nichtquadrat.
- **ERSETZEN:** den generischen Satz über quadratisches `a` durch den
  konkreten Nachweis `a=45677^2 mod p`.
- **ERSETZEN:** „Small-order points imply cofactor at least 4“ durch die
  exakte Struktur `#E(F_p)=4q` und die Punkte
  `(0,-1)`, `(±1/45677,0)`.
- **NEU EINFÜGEN:** `#E_t(F_p)=4q_t`, Primheit von `q,q_t`, Hasse- und
  Twistrelation sowie maximaler Einbettungsgrad.

### 3.13 Seite 6 – Appendix B „X301 Profile (KEX)“

- **UMBENENNEN:** „X301-v1 Raw XDH Function“.
- **ERSETZEN:** das alte Drei-Bit-Clamping durch die exakte Byte-Regel
  `k[0]&=0xfc`, `k[37]=(k[37]&0x0f)|0x10`. Damit sind Bits `2..299`
  variabel, also genau 298 Bits; der Clamp-Wert `k=N_t` wird verworfen und
  `KeyGen` zieht in diesem seltenen Fall neu.
- **ERSETZEN:** `A24=(A+2)/4` durch das neue `A24_minus` mit der vollständigen
  `AA`-Formel.
- **NEU EINFÜGEN:** feste Basis-u, striktes 38-Byte-u-Decoding,
  `KeyGen/Public/Shared`, vollständige 301-Runden-Leiter und die
  veröffentlichten Public-/Shared-Vektoren.
- **ERSETZEN:** „reject invalid or all-zero outputs“ durch die vollständige
  Regel: falsche Länge, gesetzte hohe u-Bits, `u>=p`, `Z=0`, All-zero-Ausgabe
  oder ausgeschlossener Secret-Skalar führen zu `FAIL` ohne Ersatzbytes.
- **NEU EINFÜGEN:** ausdrückliche Grenze: rohe XDH-Ausgabe, keine KDF, keine
  Authentisierung und kein fertiger Handshake.

### 3.14 Seite 6 – Appendix C „Concrete Constants“

- **BEIBEHALTEN:** die Hexdarstellung von `p`.
- **STREICHEN:** die mit `a=1` berechneten alten Werte für `A` und `A24`.
- **ERSETZEN:** Appendix C vollständig durch den Parametersatz aus Abschnitt
  6 dieser Liste oder durch eine normative, versionsgebundene Wiedergabe von
  [ed301-v1.json](../parameter/ed301-v1.json).
- **NEU EINFÜGEN:** mindestens `a,d,N,h,q`, expliziter Twist samt
  `N_t,h_t,q_t`, `A,B,A24_minus`, Basispunkt, Punktkodierung und eindeutige
  Versionskennung; für X301-v1 zusätzlich Basis-u, Clamp-Masken und den
  Ausschluss `k=N_t`.

## 4. Zwingender Versions- und Migrationshinweis

Version 1.2 MUSS ausdrücklich festhalten:

1. Die `a=1`-Kurve und die `c=44730`-Kurve sind verschiedene Kurven.
2. Alte Montgomery-Konstanten, Punkte, Schlüssel, Signaturen und Testwerte
   sind mit dem neuen Parametersatz nicht kompatibel.
3. Kein Wert aus dem v1.1-Entwurf darf unter derselben Suite- oder
   Algorithmuskennung als v1.2-Eingabe akzeptiert werden.
4. `Ed301-Sig-v1` bezeichnet ausschließlich die neue `q`-Primuntergruppe,
   den neuen Basispunkt, die festgelegte Kodierung und die eigene Hash-Domain.
5. `X301-v1` verwendet ausschließlich das neue Montgomery-Modell, die neue
   Basis-u-Koordinate und seine eigene Clamp-/Fehlerregel. u-Werte oder
   Public Keys des `a=1`-Entwurfs sind nicht kompatibel.
6. Eine versuchsweise Verifikation oder Shared-Berechnung unter mehreren
   Parameterständen ist
   verboten. Ein äußeres Format muss die Version vor der Kryptoprüfung
   eindeutig ausgewählt haben.

## 5. Neu einzufügender Negativbefund für `a=1`

Version 1.2 MUSS offen dokumentieren, warum der ursprüngliche Kandidat nicht
normiert wurde. Für

```text
E_0: x^2 + y^2 = 1 + 301*x^2*y^2
```

wurde exakt bestimmt:

```text
N_0 =
4074071952668972172536891376818756322102936790024709516523088567757405009860459412423203588

N_0 = 2^2 * 7 * 273727 * 191291054077238539
      * 2778806880828370518402978361289226106539992143950047018858348906107
```

Der größte Primfaktor hat nur 221 Bit; sein Cofaktor ist

```text
h_0 = 1466122738063207659815884
```

und hat 81 Bit. Für den expliziten quadratischen Twist ergab sich

```text
N_0,t =
4074071952668972172536891376818756322102936784639035486021471962009519960963485915607182436

N_0,t = 2^2 * 19 * 5749 * 736013 * 131180052881 * 20033072740313
        * 4820831355970401167364587956319363065593389810855266651
```

Der größte Twist-Primfaktor hat nur 182 Bit; der zugehörige Cofaktor hat 120
Bit. Der generische ECDLP-Aufwand liegt damit nur bei ungefähr 110 Bit auf der
Hauptkurve und ungefähr 91 Bit auf dem Twist. Das ist ein negativer
Parameterbefund, kein bloßer Dokumentationsmangel. `Ed301-Sig-v1` DARF auf
diesem alten Kandidaten nicht definiert werden.

Belege:
[ursprüngliche Punktzählung](../rohresultate/phase_a_pointcount_pari.txt),
[Faktorisierung](../rohresultate/phase_a_factor_orders_pari.txt) und
[Kurvenbericht](KURVENBERICHT_ED301.md).

## 6. Exakter Parametersatz, der in 1.2 einzusetzen ist

### 6.1 Transparente `a`-Regel und Edwards-Kurve

Die festgelegte, lückenlos geprüfte Regel ist

```text
s_c = 947 + c
a_c = s_c^2 mod p
c = 0,1,2,...
```

Gewählt wird der kleinste Kandidat, der die veröffentlichte
Gruppenordnungs- und Sicherheitsprüfung erfüllt. Sie verlangt insbesondere
vollständige Edwards-Bedingungen, nichtsinguläre äquivalente Modelle,
`N=4q`, `N_t=4q_t` mit hinreichend großen bewiesenen Primzahlen, keine kleinen
Einbettungsgrade bis 100, Hasse- und Twistrelation, Nichtanomalität und eine
hinreichend große fundamentale CM-Diskriminante. Die vollständige Regel steht
im [Kurvenbericht](KURVENBERICHT_ED301.md).

Alle Zähler `0..44729` scheitern, `c=44730` besteht. Die Suche wurde
lückenlos bis `50687` fortgeführt; dort existiert kein kleinerer und insgesamt
genau ein Treffer. Damit gilt

```text
c = 44730
s = 947+c = 45677
a = s^2 mod p = 2086388329 = 0x7c5bc269
d = 301 = 0x12d

p = 2^301 - 2^99 + 947
  = 4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011
  = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000003b3

E: 2086388329*x^2 + y^2 = 1 + 301*x^2*y^2  over F_p.
```

`a` ist Quadrat, `d` Nichtquadrat; die Edwards-Addition ist vollständig.

### 6.2 Hauptgruppe und expliziter Twist

```text
N = #E(F_p)
  = 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612
  = 4*q

h = 4

q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403
  = 0x800000000000000000000000000000000000016dcc80892809847fb4a312602e3a1d0be9603

t = p+1-N
  = -2039396660562211322150674408465746672142144600
```

Für `z=2`, einen quadratischen Nichtrest, ist der explizite Twist

```text
E_t: Y^2 = X^3 + a2_t*X^2 + a4_t*X

a2_t = 2233619512869490907631861401184448678229596874716216742957009632374356945814110577661827333
a4_t = 3775868568901820659765009875903393853235450873136189485348265599950038130552590587178562472

N_t = #E_t(F_p)
    = 4074071952668972172536891376818756322102936785292475840710068942732788076946225991873048412
    = 4*q_t

h_t = 4

q_t = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103
    = 0x7ffffffffffffffffffffffffffffffffffffe92337f76d7f63b804b5ced9fd1c5e2f416bd7
```

`q` und `q_t` sind formal als prim bewiesen; beide Gesamtgruppen sind
zyklisch. Es gilt `N+N_t=2p+2`. Die Einbettungsgrade sind maximal:
`ord_q(p)=q-1` und `ord_q_t(p)=q_t-1`.

### 6.3 Montgomery- und Weierstraßkonstanten

```text
B*v^2 = u^3 + A*u^2 + u

A = 1337125101468798294423667083008487580371440947467333579746761624815927501631542793281919359
  = 0xa80a4d8ae8c4deeae7d73707f20e97aa05c8b48895457b5c73233513cbc27d21510191ad97f

B = 2102386304867639485174889802292078795702081870378430469358638547115457185184343208357597462
  = 0x108367753cf71c534a92b3d6b306e9cfedd2616b675dd5c437ed96b56d10c8d99334c8cd1116

A24_minus = (A-2)/4 mod p
          = 1352799263534442616740139614956810975618594433699801520254760472424847496760878864324278092
          = 0xaa029362ba3137bab9f5cdc1fc83a5ea81722d2225515ed71ca8cd44f2f09f485440646b74c

A24_plus  = (A+2)/4 mod p
          = 1352799263534442616740139614956810975618594433699801520254760472424847496760878864324278093
          = 0xaa029362ba3137bab9f5cdc1fc83a5ea81722d2225515ed71ca8cd44f2f09f485440646b74d
          # nur Vergleichswert, nicht Leiterkonstante der gewählten Formel
```

Unter `X=B*u`, `Y=B^2*v` lautet das Weierstraßmodell

```text
Y^2 = X^3 + a2*X^2 + a4*X

a2 = 3153845732769231540084376389001602500166266831024044622114644948628909715613041620838510172
a4 = 943967142225455164941252468975848463308862718284047371337066399987509532638147646794640618
```

Die birationalen Abbildungen in beide Richtungen, einschließlich Identität,
Ordnung-2-Punkt und aller möglichen Nullnennerfälle, MÜSSEN aus
[ED301-v1](../spezifikation/ED301-v1.md) übernommen oder normativ darauf
verwiesen werden.

### 6.4 Basispunkt

Die transparente Ableitung verwendet

```text
DST = ASCII("ED301-BASEPOINT-DERIVATION-v1")
input = DST || I2OSP(counter,4,big-endian)
SHAKE256 output = 38 byte
```

Nach Maskierung der Bits `301..303`, Rejection Sampling, Wahl des geraden
Kandidaten-`x` und Clearing mit `[4]` ist bereits `counter=0` gültig:

```text
G.x = 114483960210649758260691970228447544333115946824833551736797985468026643833345600929055
G.y = 3123599847077067352547410063473606051762622289826321814465731066121453938271612909425522539

ENC(G) =
6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898

G.u = 1067917942141295978366266158278333061632895636270240461974100298644709548352069314007836251
G.v = 440719678915870457116701635146449947572460444481575851594677144469352806862244984556749020
```

Es gilt `G != O` und `[q]G=O`; wegen der Primheit von `q` besitzt `G` exakte
Ordnung `q`.

### 6.5 Kanonische Kodierungen und Cofactor-Regeln

Version 1.2 MUSS bitgenau festlegen:

- Feldelement: exakt 38 Byte little-endian, Bits `301..303` null, Wert `<p`;
- Edwards-Punkt: `y` in Bits `0..300`, Bits `301,302` null, Bit `303` ist die
  LSB des kanonischen `x`; `y<p`, eindeutige Rekonstruktion, bei `x=0` nur
  Vorzeichen null;
- Skalar: exakt 38 Byte little-endian, strikt `0<=S<q`, keine Reduktion einer
  nichtkanonischen Eingabe;
- allgemeines Edwards-Clearing: `[4]P`, danach Identität je nach
  Verwendungszweck verwerfen;
- strikter öffentlicher Primuntergruppenpunkt: kanonisch dekodiert,
  `P!=O`, `[q]P=O`;
- kein Clamping für Ed301-Sig-v1-Skalare.

Die vollständigen Ablehnungs- und Rekonstruktionsregeln stehen normativ in
[ED301-v1](../spezifikation/ED301-v1.md). Die hiervon verschiedene
Secret-Clamp- und u-Kodierung von X301-v1 steht ausschließlich in der
[X301-v1-Spezifikation](../spezifikation/X301-v1.md).

## 7. Zwingende Sicherheitsformulierung

Die Sicherheitsangabe darf nicht auf die Feldbitlänge gerundet werden. Aus
der bewiesenen Primordnung folgt für die übliche Pollard-rho-Erwartung
`sqrt(pi*q/2)`:

```text
149.825748064736... Bit Gruppenoperationen.
```

Mit Negationsabbildung und Erwartung `sqrt(pi*q/4)` sind es

```text
149.325748064736... Bit Gruppenoperationen.
```

Die Twistwerte stimmen auf den gezeigten Stellen praktisch überein. Zulässig
ist „approximately 150-bit generic classical security“. Unzulässig sind
„at least 150 bits“, „strictly 150 bits“ oder eine unqualifizierte Ableitung
von 150 Bit allein aus der 301-Bit-Feldgröße.

Empfohlener englischer Ersatztext:

> The audited prime-order subgroups provide approximately 150-bit generic
> classical ECDLP security. Under the standard Pollard-rho expectation the
> estimate is 149.826 bits of group operations; accounting for the negation
> map gives a conservative estimate of 149.326 bits. This is not a claim of
> at least 150.000 bits and does not constitute a production security audit.

Für X301-v1 ist zusätzlich eine getrennte Grenze zwingend. Das Clamping lässt
genau die Positionen `2..299` variabel und verwirft anschließend
`k=N_t`; damit verbleiben `2^298-1` akzeptierte geklampte Skalare. Ein
generischer Intervallangriff gegen diese bekannte Menge liegt in der
Größenordnung von `2^149` Gruppenoperationen. Zulässig ist daher
„approximately 149-bit generic private-exponent security“; die etwas höhere
Bewertung der vollen Kurvengruppe darf nicht auf das X301-Secret-Format
übertragen werden.

Zusätzlich sind maximaler Einbettungsgrad, Nichtanomalität,
Nichtsupersingularität sowie der CM-/Endringbefund aus dem
[Kurvenbericht](KURVENBERICHT_ED301.md) kurz zu dokumentieren. Die
Endringleiterbestimmung bleibt als begründete Vulkaninferenz zu kennzeichnen;
die konservative Sicherheitsbewertung deckt beide möglichen Leiter ab.

## 8. Zwingend neuer Abschnitt „Ed301-Sig-v1“

Das Whitepaper darf eine Kurve nicht länger als Signaturverfahren behandeln.
Ein technischer Abschnitt MUSS entweder die vollständige
[Signaturspezifikation](../spezifikation/Ed301-Sig-v1.md) normativ einbinden
oder sie vollständig und ohne Abweichung wiedergeben. Eine verkürzte
Übersicht darf folgende festen Eigenschaften nennen:

```text
Name:             Ed301-Sig-v1
Kurve:            ED301-v1, Primuntergruppe <G> der Ordnung q
Secret key:       38-Byte-Seed
Public key:       ENC(A), 38 Byte
Signatur:         ENC(R) || ENC(S), 76 Byte
XOF:              SHAKE256
Hash-to-scalar:   64 XOF-Byte, little-endian als Integer, mod q
Context:          0..255 opake Byte
Message length:   0..2^64-1, Länge vor dem ersten Nachrichtenbyte bekannt
Modus:            pure mode 0x00, kein Prehash
Untergruppe:      strikt; A,R != O und [q]A=[q]R=O
Skalare:          kein Clamping; S muss kanonisch und <q sein
Gleichung:        [S]G = R + [k]A
```

Folgende Punkte dürfen nicht verkürzt oder offengelassen werden:

- die feste Domain `Ed301-Sig-v1`, Version und Modus;
- typisierte und längenpräfigierte Frames für Schlüsselableitung,
  Nonce-Präfix, Nonce und Challenge;
- deterministische Retry-Regeln für `s=0` und `r=0`;
- Bindung von öffentlichem Schlüssel, Kontext, Nachricht und `R`;
- kanonische Punkt- und Skalardekodierung;
- alle Identitäts-, Torsions-, Mischordnungs- und falschen Domainfälle;
- die Trennung von Signaturkern und jeder anwendungsspezifischen
  Serialisierung.

`Ed301-Sig-v1` signiert opake Bytes. Es führt keine Unicode-Normalisierung
aus und interpretiert weder Identität noch Historie, Zeit, Erinnerung oder
andere Anwendungssemantik.

## 9. Zwingend neuer Abschnitt „X301-v1 Raw XDH Function“

Die mathematische Prüfung fällt für Hauptkurve und Twist positiv aus.
[X301-v1](../spezifikation/X301-v1.md) ist inzwischen eine vollständig
definierte rohe XDH-Funktion und MUSS in Version 1.2 als solche – weder weniger
noch mehr – dargestellt werden.

Eine verkürzte Übersicht darf folgende festen Eigenschaften nennen:

```text
Name:              X301-v1
Secret input:      exakt 38 rohe Byte aus einem CSPRNG
Public/peer u:     exakt 38 Byte little-endian, Bits 301..303 null, u<p
Clamping:          Bits 0,1,301,302,303 löschen; Bit 300 setzen
Variable Bits:     exakt 298, Positionen 2..299
Sonderfall:        geklamptes k=N_t ist ungültig; KeyGen zieht neu
Basis:             feste u-Koordinate der ED301-Basis G
Leiter:            immer 301 Runden, A24_minus und AA-Formel
Fehler:            ungültige Kodierung, Z=0 oder All-zero -> FAIL
Schnittstellen:     KeyGen, Public, Shared und gemeinsame X301-Kernfunktion
Sicherheitsgrenze: ungefähr 2^149 generischer privater Exponentensuchaufwand
```

Hauptkurve und Twist besitzen jeweils Cofaktor `4`; das durch vier teilbare
Clamping beseitigt diesen rationalen Cofaktor. Im Clamp-Intervall existiert
kein durch vier teilbares `q`-Vielfaches. Auf dem Twist ist `N_t=4q_t` das
einzige annihilierende Vielfache und wird ausdrücklich samt allen 64 rohen
Secret-Präbildern abgelehnt.

`X301-v1` liefert eine rohe 38-Byte-u-Ausgabe. Es definiert ausdrücklich
keine KDF, keine Rollen- oder Transkriptbindung, keine Authentisierung, keine
Schlüsselbestätigung und keinen vollständigen Handshake. Die Rohausgabe DARF
nicht unmittelbar als symmetrischer Schlüssel verwendet werden. Ein sicherer
Kanal benötigt weiterhin ein gesondertes, analysiertes Protokoll.

## 10. Nachweise und Testvektoren, die 1.2 referenzieren muss

Version 1.2 SOLLTE einen technischen Nachweisindex mit mindestens folgenden
Artefakten enthalten:

- [normativer Parametersatz](../parameter/ed301-v1.json),
  SHA-256
  `23cb60255848176320d8938cb1856d469eb91455868da4078526dfb26ef6806f`;
- [normative Kurvenspezifikation](../spezifikation/ED301-v1.md),
  SHA-256
  `1e52b0ac5ffcd54ccf67f1b54d1f39d75f397aabda41fd2c3ab6e3b955d9b652`;
- [normative XDH-Funktion X301-v1](../spezifikation/X301-v1.md),
  SHA-256
  `214f5385747f859e39e68407bcdbde49776f7e3d0b37de6e1aa6c1663352b592`;
- [normative Signaturspezifikation](../spezifikation/Ed301-Sig-v1.md),
  SHA-256
  `743e26887edcdd2aab2825d91716e7d52a6da311fdf47c5d5dec092fdca82c64`;
- [vollständiger Kurvenbericht](KURVENBERICHT_ED301.md);
- [PARI-Gesamtaudit](../scripts/audit_c44730_full_reproducibility.gp) und
  [Rohresultat](../rohresultate/audit_c44730_full_reproducibility_pari.txt);
- [unabhängiger Python-Ordnungsnachweis](../scripts/audit_candidate_c44730_order_witness.py)
  mit [Rohresultat](../rohresultate/audit_candidate_c44730_order_witness_python.txt);
- [Basispunktableitung](../scripts/derive_c44730_basepoint.py) und
  [PARI-Gegenprüfung](../rohresultate/c44730_basepoint_crosscheck_pari.txt);
- [positive Signaturvektoren](../vektoren/ed301-sig-v1-positive.json),
  SHA-256
  `6faaf9e2e5ec6d0f66c90a886ce387ce0ca4eca5d0c7e82ab75cfe1b4fa0ce0c`;
- [negative und interne Vektoren](../vektoren/ed301-sig-v1-negative.json),
  SHA-256
  `6fa3fcab422db0ec459fcb5db61987e25b53650705ec7ad1fadb56f94b7ac945`;
- [positive X301-v1-Vektoren](../vektoren/x301-v1-positive.json),
  SHA-256
  `aa617c6aebd3ddc16e791cf123d782c064e839a184b0e81d7597b39d1c7be88c`;
- [negative und interne X301-v1-Vektoren](../vektoren/x301-v1-negative.json),
  SHA-256
  `f757fbdf7e130e6d613ac699dbbe8e7591c20877b9444096fbf32a097ae32766`;
- [unabhängige Signatur-Gegenimplementierung](../gegenpruefung/README.md) mit
  [maschinenlesbarem Ergebnis](../gegenpruefung/node-countercheck-result.json);
- [unabhängige X301-v1-Gegenimplementierung](../gegenpruefung/x301/README.md)
  mit [maschinenlesbarem Ergebnis](../gegenpruefung/x301/node-countercheck-result.json).

Der gegenwärtige Interoperabilitätsstand lautet:

- 20 Kurvenreferenztests bestanden;
- Kurven- und Signaturreferenz gemeinsam 47 Tests bestanden;
- fünf positive Signaturvektoren;
- 41 echte Negativ-Verifikationsvektoren korrekt abgelehnt;
- sieben interne Framing-/Null-/Retry-Vektoren bestanden;
- unabhängige Node.js-Implementierung: 42 eigene Tests, anschließend alle
  Signatur-Vergleichsvektoren und 330 Assertions bestanden;
- X301-v1: zehn positive Funktionsvektoren, zwei Agreement-Paare, 18 negative
  API-, zwei äußere Parser- und zwei interne Vektoren bestanden;
- unabhängige X301-v1-Implementierung: 32 eigene Tests vor Vektorsichtung,
  alle 64 gemeinsamen Clamp-Präbilder, alle 64 ausgeschlossenen
  `N_t`-Präbilder und anschließend 1068 Assertions bestanden.

Diese Übereinstimmung ist eine starke interne Gegenprüfung, aber kein externer
Kryptoaudit.

## 11. Zwingender Abschnitt zu Produktionsgrenzen

Version 1.2 MUSS am Anfang und im Sicherheitsteil klarstellen:

- ED301 ist eine neue projektspezifische Kurve und kein breit standardisierter
  Ersatz für etablierte Kurven.
- Die vorhandenen Python- und JavaScript-Implementierungen dienen Audit,
  Reproduktion und Interoperabilität. Sie sind variabelzeitig und nicht gegen
  Timing-, Cache-, Fault- oder Invalid-Input-Angriffe gehärtet.
- Eine mathematisch geeignete Kurve sowie bytegenaue XDH- und
  Signaturspezifikationen sind noch keine Produktionsfreigabe.
- Reale Nutzung mit hohen Schutzanforderungen setzt unabhängigen externen
  Kryptoaudit, konstantzeitliche Implementierungen, Seitenkanaltests, sichere
  Zufallsquellen, Schlüsselverwaltung und Integrationsprüfung voraus.
- Klassische Sicherheit impliziert keine Post-Quantum-Sicherheit. Ein
  Hybridprofil ist ein separates Verfahren und darf nicht durch eine bloße
  Empfehlung ohne kombinierte Verifikations- und Downgrade-Regeln als
  implementiert gelten.

Empfohlener englischer Statussatz:

> ED301-v1, X301-v1, and Ed301-Sig-v1 are technically specified and
> independently cross-implemented for audit and interoperability. They have
> not received an independent external production cryptographic audit, and
> the accompanying reference implementations are not side-channel hardened.

## 12. Empfohlene technische Gliederung von Whitepaper 1.2

Die folgende Gliederung minimiert Mehrdeutigkeit, ohne nichttechnische
Abschnitte dieser Liste zu bearbeiten:

1. **Status, Scope and Naming** – ED301-v1, X301-v1 und Ed301-Sig-v1 trennen;
2. **Symbolic Parameter Provenance** – Symbolik als Herkunft, nicht als
   Sicherheitsbeweis;
3. **Rejected `a=1` Candidate** – exakter negativer Befund;
4. **Transparent Parameter Selection** – Regel und erster Treffer `c=44730`;
5. **Normative ED301-v1 Parameters** – Feld, Edwards, Montgomery,
   Weierstraß, Twist, Ordnungen;
6. **Group Arithmetic and Encodings** – vollständige Addition,
   Cofactor-Regeln, Abbildungen und Ausnahmefälle;
7. **Basepoint Derivation** – SHAKE256-Verfahren und Zwischenwerte;
8. **X301-v1 Raw XDH Function** – Clamping, strikte u-Kodierung,
   `A24_minus`, Leiter, Public/Shared und Fehlerregeln; keine KDF und kein
   authentisierter Handshake;
9. **Ed301-Sig-v1** – vollständiger normativer Verweis, Schnittstellen und
   Grenzen;
10. **Security Analysis** – Primzahlbeweise, Ordnungen, Twist, MOV, CM und
    ehrliche Pollard-rho-Angabe;
11. **Test Vectors and Independent Countercheck** – positive, negative und
    interne Vektoren;
12. **Implementation and Production Limits** – keine Produktionsfreigabe;
13. **Separate Application and Future Profiles** – nur als klar abgegrenzte
    Verweise, nicht als Eigenschaften der Kurve.

## 13. Technische Abnahmecheckliste für das neue PDF

Vor Freigabe einer Whitepaper-Datei mit Versionsnummer 1.2 ist mechanisch zu
prüfen:

- [ ] Nirgendwo wird die normative ED301-Kurve noch mit `a=1` definiert.
- [ ] Alte `a=1`-Konstanten für `A`, `B` und `A24` kommen nur im klar
      bezeichneten historischen Negativabschnitt vor.
- [ ] `c=44730`, `s=45677` und `a=2086388329` sind identisch zum
      Parametersatz.
- [ ] `N=4q` und `N_t=4q_t` sowie sämtliche Dezimal- und Hexwerte stimmen mit
      `ed301-v1.json` überein.
- [ ] Das konkrete Twistmodell mit `z=2` ist angegeben.
- [ ] Der ECPP-Future-Work-Punkt ist entfernt und das vorhandene Zertifikat
      verlinkt beziehungsweise beigelegt.
- [ ] Weder `expected h=4` noch ein anderer vorläufiger Cofaktor verbleibt.
- [ ] `[8]` wird weder als Edwards-Clearing noch als Signatur-Clamping
      verwendet.
- [ ] Die normative Leiter verwendet `A24_minus` mit der `AA`-Formel.
- [ ] X301-v1 löscht die beiden niedrigen Scalar-Bits, setzt Bit `300`,
      löscht Bits `301..303` und weist exakt 298 variable Bits aus.
- [ ] Der Clamp-Sonderwert `k=N_t` sowie alle seine rohen Präbilder werden
      abgelehnt; `KeyGen` zieht neu.
- [ ] X301-v1 verwendet strikt kanonische 38-Byte-u-Eingaben und behandelt
      `Z=0` sowie All-zero als `FAIL`.
- [ ] Reproduzierbare Leiter-, Public- und Shared-Vektoren sind vorhanden.
- [ ] Feldelement-, Punkt- und Skalarkodierung sind bitgenau und kanonisch.
- [ ] Basispunktableitung und exakte Ordnung `q` sind enthalten.
- [ ] „Approximately 150 bit“ ist mit 149,826/149,326 Bit erläutert und nicht
      als harte Untergrenze formuliert.
- [ ] X301-v1 wird getrennt mit ungefähr `2^149` privatem
      Exponentensuchaufwand bewertet.
- [ ] Eine Kurve wird nicht mehr als Signaturverfahren bezeichnet.
- [ ] Jede Signaturbehauptung verweist eindeutig auf `Ed301-Sig-v1`.
- [ ] X301-v1 wird als vollständig definierte rohe XDH-Funktion dargestellt,
      aber nicht als KDF, authentisierter Handshake oder sicherer Kanal.
- [ ] Semantische oder historische Konsistenz wird nicht als Ergebnis einer
      Signaturprüfung behauptet.
- [ ] Die Produktionswarnung steht sichtbar im Dokument.
- [ ] Die unabhängigen Gegenimplementierungen und die positiven wie negativen
      Signatur- und X301-Vektoren sind referenziert.
- [ ] Es existieren keine kryptographisch relevanten Platzhalter oder
      uneindeutigen Beispielwerte.
- [ ] Das neue PDF erhält einen neuen Dateinamen; Version 1.1 bleibt
      unverändert archiviert.

Erst wenn alle Punkte erfüllt sind, ist die technische Migration von
Whitepaper 1.1 zu 1.2 konsistent. Auch dann bleibt eine reale
Produktionsfreigabe ausdrücklich ein gesonderter Schritt.
