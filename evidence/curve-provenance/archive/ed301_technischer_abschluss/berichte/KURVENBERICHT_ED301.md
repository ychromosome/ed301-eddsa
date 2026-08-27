# Technischer Kurvenbericht ED301

Stand: 12. Juli 2026  
Gegenstand: mathematischer Abschluss der Phasen A und B für ED301 mit dem
deterministisch ausgewählten Kurvenparameter `c = 44730`

## 1. Ergebnis und Geltungsbereich

Der ursprüngliche Kurvenansatz mit `a = 1` ist für die beabsichtigte
Signaturgruppe ungeeignet: Hauptkurve und Twist besitzen große Cofaktoren und
nur 221 beziehungsweise 182 Bit große größte Primfaktoren. Der transparente,
lückenlos geprüfte Ersatzparameter

```text
c = 44730
s = 947 + c = 45677
a = s^2 mod p = 2086388329
```

behebt diesen Befund. Hauptkurve und expliziter quadratischer Twist haben
jeweils Ordnung `4 * Primzahl`, sind zyklisch, nicht anomal, nicht
supersingulär und besitzen maximalen Einbettungsgrad. Die mathematische
Eignungsprüfung fällt daher positiv aus.

Das Urteil ist bewusst geteilt:

- **Ed301-Sig-v1:** Die Kurvenparameter, Primordnung, Cofaktorbehandlung,
  Basispunktableitung und kanonische Kodierung sind für ein Signaturprofil
  geeignet. Das mathematische Parameterurteil ist positiv.
- **X301:** Die Parameter sind auch für eine x-only-Montgomery-Leiter positiv
  beurteilt. Die später getrennt fertiggestellte
  [X301-v1-Spezifikation](../spezifikation/X301-v1.md) normiert Skalarbildung,
  Clamping, Eingabepolitik sowie Kleinordnungs- und Nullergebnisbehandlung.
  Diese Regeln werden nicht aus Ed301-Sig-v1 abgeleitet. KDF und
  Transkriptbindung bleiben weiterhin Aufgaben eines darüberliegenden
  Sitzungsprofils.

Der Bericht enthält keine narrative Spezifikation. Er bewahrt lediglich die
explizit vorgegebenen Zahlen `301`, `99` und `947` in ihrer technischen Rolle.

## 2. Unveränderter symbolischer Kern

Unverändert bleiben

```text
p = 2^301 - 2^99 + 947
  = 4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011

d = 301
```

Damit bleiben erhalten:

- `301` als Bitlänge des Primfelds und als Edwards-Parameter `d`,
- `99` als Subtraktionsexponent des Pseudo-Mersenne-Moduls,
- `947` als Feldkonstante und als Offset der neuen `a`-Ableitung.

Es gilt `p mod 8 = 3`. Ein 13-stufiges ECPP-Zertifikat beweist die Primheit
von `p`; es wurde im Gesamtaudit frisch erzeugt und validiert. Das gespeicherte
Zertifikat liegt in [interner PARI-Form](../zertifikate/p_ecpp_internal.pari),
[menschenlesbar](../zertifikate/p_ecpp_human.txt), im
[Primo-Format](../zertifikate/p_ecpp_primo.txt) und als optionaler
[Magma-Export](../zertifikate/p_ecpp_magma.m) vor. Die Neuberechnung ist im
[vollständigen PARI-Rohresultat](../rohresultate/audit_c44730_full_reproducibility_pari.txt)
dokumentiert.

## 3. Ausgangsbefund für `a = 1`

Die ursprüngliche Kurve

```text
x^2 + y^2 = 1 + 301*x^2*y^2  über F_p
```

ist zwar als algebraische Kurve verwendbar, erfüllt aber die angestrebten
Gruppenparameter nicht. Die direkte SEA-Zählung ergab

```text
N_0 = 4074071952668972172536891376818756322102936790024709516523088567757405009860459412423203588

N_0 = 2^2 * 7 * 273727 * 191291054077238539
      * 2778806880828370518402978361289226106539992143950047018858348906107
```

Der größte Primfaktor hat nur 221 Bit; sein Cofaktor ist

```text
h_0 = 1466122738063207659815884
```

und damit 81 Bit lang. Für den expliziten Twist mit Nichtrest `z = 2` ergab
sich

```text
N_0,t = 4074071952668972172536891376818756322102936784639035486021471962009519960963485915607182436

N_0,t = 2^2 * 19 * 5749 * 736013 * 131180052881 * 20033072740313
        * 4820831355970401167364587956319363065593389810855266651
```

Hier ist der größte Primfaktor nur 182 Bit und der Cofaktor 120 Bit lang. Das
ist kein bloßer Dokumentationsmangel, sondern ein negativer kryptographischer
Parameterbefund. Reproduzierbar sind Zählung und Faktorisierung in
[phase_a_pointcount.gp](../scripts/phase_a_pointcount.gp),
[phase_a_pointcount_pari.txt](../rohresultate/phase_a_pointcount_pari.txt) und
[phase_a_factor_orders_pari.txt](../rohresultate/phase_a_factor_orders_pari.txt).

## 4. Transparente `a`-Regel und lückenlose Auswahl

Die Reparatur ändert weder `p` noch `d`. Statt des unbegründeten Literals
`a = 1` gilt die deterministische Folge

```text
s_c = 947 + c
a_c = s_c^2 mod p
c = 0, 1, 2, ...
```

Gewählt wird der kleinste Zähler, dessen Kandidat den veröffentlichten
Prüfvektor vollständig erfüllt:

1. `a != 0`, `d != 0`, `a != d`, `a` ist Quadrat und `d` Nichtquadrat;
2. das äquivalente Montgomery-Modell ist nicht singulär und
   `j` ist weder `0` noch `1728`;
3. SEA liefert exakte Ordnungen `N` und `N_t`, beide kongruent `4 mod 8`;
4. `N = 4q` und `N_t = 4q_t`, wobei `q` und `q_t` prim sind und jeweils
   mindestens 299 Bit Länge besitzen;
5. für `1 <= k <= 100` tritt kein kleiner Einbettungsgrad auf;
6. Hasse-Grenze, Twistrelation und Nichtanomalität gelten;
7. die fundamentale CM-Diskriminante hat Betrag größer als `2^100`.

Der Suchworker ist [search_a_worker.gp](../scripts/search_a_worker.gp), die
lückenlose Orchestrierung [search_a_continuous.py](../scripts/search_a_continuous.py).
Die 355 gespeicherten Blockresultate decken zusammen `c = 0..50687` ohne
Lücke ab. Jeder Block enthält seine Grenzen und die exakte Anzahl geprüfter
Kandidaten. Es gibt genau einen Treffer, dokumentiert im
[Trefferblock 44544..44799](../rohresultate/search_44544_44799_worker_1.txt).
Die spätere 256er-Blockkampagne ist zusätzlich in
[search_continuous_summary.json](../rohresultate/search_continuous_summary.json)
zusammengefasst; die früheren Blöcke beginnen bei
[0..31](../rohresultate/search_0_31_worker_0.txt) und reichen ohne Übergangslücke
bis [21248..21503](../rohresultate/search_21248_21503_worker_15.txt).

Da alle Zähler `0..44729` negativ und `44730` positiv geprüft wurden, ist
`c = 44730` nach der festgelegten Regel nachweislich der kleinste Treffer.

Der rein lesende
[Suchtranskript-Prüfer](../scripts/verify_search_transcript.py) validiert
zusätzlich jede der 355 Workerdateien einschließlich Dateiname, Grenzen,
Worker-ID, Prüfanzahl, Fehlermarkern und sämtlichen Feldern eines Treffers. Er
weist 50.688 eindeutige Zähler, lückenlose Abdeckung `0..50687`, keinen Treffer
vor `44730` und genau einen Treffer bei `44730` aus. Die einzige
Mehrfachabdeckung ist eine konsistente historische Wiederholung von `c=0`.

## 5. Festgelegte Kurve und äquivalente Modelle

Die normative twisted-Edwards-Kurve lautet

```text
E: 2086388329*x^2 + y^2 = 1 + 301*x^2*y^2  über F_p.
```

Es gilt

```text
Legendre_p(a) =  1
Legendre_p(d) = -1
```

bei `a,d != 0` und `a != d`. Damit sind die Voraussetzungen der vollständigen
twisted-Edwards-Additionsformel erfüllt.

Mit

```text
A = 2*(a+d)/(a-d) mod p
  = 1337125101468798294423667083008487580371440947467333579746761624815927501631542793281919359

B = 4/(a-d) mod p
  = 2102386304867639485174889802292078795702081870378430469358638547115457185184343208357597462
```

entsteht das Montgomery-Modell

```text
B*v^2 = u^3 + A*u^2 + u.
```

Unter `X = B*u`, `Y = B^2*v` wird daraus

```text
Y^2 = X^3
    + 3153845732769231540084376389001602500166266831024044622114644948628909715613041620838510172*X^2
    + 943967142225455164941252468975848463308862718284047371337066399987509532638147646794640618*X.
```

Weil `p mod 8 = 3`, ist `z = 2` ein quadratischer Nichtrest. Der in allen
Prüfungen verwendete explizite quadratische Twist ist

```text
E_t: Y^2 = X^3
     + 2233619512869490907631861401184448678229596874716216742957009632374356945814110577661827333*X^2
     + 3775868568901820659765009875903393853235450873136189485348265599950038130552590587178562472*X.
```

Das ist die konkrete Regel `a2 -> z*a2`, `a4 -> z^2*a4`; der Begriff
„Twist“ bleibt somit nicht implizit. Modellableitung, Diskriminanten und
Nichtsingularität werden gemeinsam im
[Gesamtaudit-Skript](../scripts/audit_c44730_full_reproducibility.gp) geprüft.

## 6. Exakte Ordnungen und unabhängiger Nachweis

Die vier direkten PARI-Läufe `ellsea(E)`, `ellsea(E_t)`, `ellcard(E)` und
`ellcard(E_t)` stimmen überein. Es gilt exakt

```text
N   = 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612
    = 4 * q

q   = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403

N_t = 4074071952668972172536891376818756322102936785292475840710068942732788076946225991873048412
    = 4 * q_t

q_t = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103

h = h_t = 4.
```

`q` hat 300 Bit bei `log2(q) = 299.000000... + epsilon`; `q_t` hat 299
Bit bei `log2(q_t) = 299.000000... - epsilon`. Ferner gilt exakt

```text
N + N_t = 2*p + 2.
```

### Unabhängige Python-Gegenprüfung

Die Ordnungen hängen nicht allein vom PARI-Point-Counting ab. Das Skript
[audit_candidate_c44730_order_witness.py](../scripts/audit_candidate_c44730_order_witness.py)
verwendet ausschließlich Python-Integerarithmetik und eine eigenständige
affine Weierstraß-Gruppenarithmetik; es importiert weder PARI noch eine
Kurvenbibliothek oder Point-Counting-Code.

Für Hauptkurve und Twist konstruiert es jeweils aus dem deterministischen
Startwert `X = 2` einen nichttrivialen Punkt `W = [4]P` und prüft

```text
[q]W = O       beziehungsweise       [q_t]W_t = O.
```

Da `q` und `q_t` separat als prim bewiesen sind, haben die beiden Zeugen
exakt diese Primordnung. Das ganzzahlige Hasse-Intervall wird anschließend
direkt berechnet. In ihm liegt für die jeweilige Primzahl genau ein
Vielfaches; der eindeutige Multiplikator ist in beiden Fällen `4`. Folglich
sind `#E(F_p) = 4q` und `#E_t(F_p) = 4q_t` unabhängig vom SEA-Code bewiesen.
Punktkoordinaten, Intervallgrenzen und alle Zwischenergebnisse stehen im
[Python-Rohresultat](../rohresultate/audit_candidate_c44730_order_witness_python.txt),
das mit `independent_order_verification=pass` endet.

Diese reine Python-Gruppenarithmetik zusammen mit der Hasse-Eindeutigkeit ist
eine unabhängige zweite Ordnungsverifikation. Eine Magma-Ausführung ist daher
**kein offener Pflichtpunkt**. Die vorhandenen Magma-Exporte bleiben eine
optionale zusätzliche Prüfung.

## 7. Primzahlnachweise und vollständige Faktorisierungen

Für beide großen Untergruppenprimzahlen bestehen je zwei methodisch getrennte
formale Beweispfade:

1. ein ECPP-Zertifikat mit 11 Schritten für `q` und 15 Schritten für `q_t`,
   jeweils frisch durch PARI validiert;
2. ein separates `N-1`- beziehungsweise BLS-Zertifikat.

Die ECPP-Ketten wurden darüber hinaus durch
[eigenständige Python-ECPP-Arithmetik](../scripts/verify_c44730_ecpp_independent.py)
bis zu vollständig durch Division geprüften Endprimzahlen nachvollzogen:
[q-Ergebnis](../rohresultate/c44730_q_ecpp_independent_python.txt) und
[Twist-Ergebnis](../rohresultate/c44730_q_twist_ecpp_independent_python.txt)
enden beide mit `independent_certificate_valid=1`. Die BLS-Zertifikate wurden
ebenfalls ohne PARI-Primalitätsroutine durch den
[Python-N−1-Prüfer](../scripts/verify_c44730_nminus1_bls_independent.py)
validiert; siehe [q](../rohresultate/c44730_q_nminus1_bls_independent_python.txt)
und [q_t](../rohresultate/c44730_q_twist_nminus1_bls_independent_python.txt).

Die internen Zertifikate sind direkt verfügbar:

- [ECPP für q](../zertifikate/c44730_q_ecpp_internal.pari) und
  [ECPP für q_t](../zertifikate/c44730_q_twist_ecpp_internal.pari),
- [BLS N−1 für q](../zertifikate/c44730_q_nminus1_bls_internal.pari) und
  [BLS N−1 für q_t](../zertifikate/c44730_q_twist_nminus1_bls_internal.pari).

Für die Einbettungsgradbeweise wurden auch `q-1` und `q_t-1` vollständig und
mit bewiesenen Primfaktoren zerlegt:

```text
q - 1 = 2 * 3 * 83 * 103 * 487
        * 8071538763312550939901261
        * 10140257736222944349715877
        * 498158843412220847318631521539897

q_t - 1 = 2 * 11
          * 46296272189420138324282856554758594569351554378323589098978056167418046328934386271284641.
```

Rekomposition und Primheit sämtlicher Faktoren sind im
[Zertifikats-/Sicherheitsrohresultat](../rohresultate/c44730_q_qtwist_primality_security_pari.txt)
und erneut im [Gesamtaudit](../rohresultate/audit_c44730_full_reproducibility_pari.txt)
bestätigt.

## 8. Trace, Hasse, Gruppenstruktur und Einbettungsgrade

Der Frobenius-Trace ist

```text
t   = p + 1 - N
    = -2039396660562211322150674408465746672142144600

t_t = -t.
```

Damit gelten die Hasse-Grenze `t^2 <= 4p` und die Twistrelation unmittelbar.
`t != 0`, `N != p` und `N_t != p`; beide Kurven sind weder supersingulär noch
anomal. PARI bestimmt die abstrakten Gruppen als

```text
E(F_p)   ~= Z/(N)Z
E_t(F_p) ~= Z/(N_t)Z.
```

Beide Gruppen sind also zyklisch. Für die Edwards-Kurve ist zusätzlich der
Punkt

```text
(x,y) = (1/45677 mod p, 0)
```

von exakter Ordnung `4` explizit nachgewiesen; er verdoppelt zu `(0,-1)`.

Mit den vollständigen Faktorisierungen von `q-1` und `q_t-1` sowie je einem
Nichtgleichheitszeugen für jeden Primteiler wurde bewiesen:

```text
ord_q(p)     = q - 1
ord_q_t(p)   = q_t - 1.
```

Die Einbettungsgrade sind damit maximal. Insbesondere existiert kein kleiner
MOV-/FR-Einbettungsgrad; die direkte Suche `k = 1..100` ist leer und der
exakte Ordnungsbeweis schließt auch alle darüber hinausgehenden echten Teiler
aus.

## 9. CM-, j- und Endringbefund

Die Invarianten lauten

```text
j = 3318721210061579742884597494500760000843802228441518889012274657523963748189585376924976265

Delta_pi = t^2 - 4p
         = -12137149071563589304614945125775576912493244030482643957703903238011574008842143168751612044

D_K = -3034287267890897326153736281443894228123311007620660989425975809502893502210535792187903011

Delta_pi = 2^2 * D_K,       f_pi = 2.
```

`j` ist weder `0` noch `1728`; `D_K` ist eine fundamentale Diskriminante.
Der Betrag der Frobeniusdiskriminante ist vollständig faktorisiert:

```text
|Delta_pi| = 2^2 * 92377 * 35332661563307
             * 10858182674212290997273094143007
             * 85616869318705925510845993428767960358607.
```

Da der Endringleiter den Frobeniusleiter teilt, kommen zunächst nur Leiter
`1` oder `2` in Betracht. Die Faktorisierung von `Phi_2(j,Y)` über `F_p` hat
Gradmuster `[1,2]`; gemeinsam mit `D_K mod 8 = 5`, `f_pi = 2` und der
zyklischen Gruppenstruktur ergibt die gewöhnliche 2-Isogenie-Vulkananalyse
die belastbare **Inferenz**, dass der tatsächliche Endringleiter `2` ist und
die Endringdiskriminante `Delta_pi` lautet. Dieser Punkt wird als Inferenz und
nicht als extern zertifizierter Endringalgorithmus ausgewiesen.

Die Sicherheitsbewertung hängt nicht von der stärkeren Inferenz ab. Sie setzt
konservativ sogar den maximalen Endring mit Leiter `1` an. Für jedes
nichtskalare CM-Element ist dessen Grad dann mindestens

```text
ceil(|D_K|/4)
= 758571816972724331538434070360973557030827751905165247356493952375723375552633948046975753
> 2^298.574886.
```

Damit ist keine kleine, für eine GLV-artige Beschleunigung relevante
nichtskalare CM-Endomorphie erkennbar.

## 10. Generische Sicherheit: ehrliche Formulierung

Für die Standarderwartung von Pollard rho,
`sqrt(pi*n/2)` Gruppenoperationen, ergeben sich

```text
Hauptgruppe: 149.825748064736... Bit
Twist:       149.825748064736... Bit.
```

Unter Ausnutzung der Negationsabbildung, `sqrt(pi*n/4)`, sind es

```text
Hauptgruppe: 149.325748064736... Bit
Twist:       149.325748064736... Bit.
```

Auf drei Dezimalstellen ist die korrekte Angabe daher **149,826 Bit**
beziehungsweise **149,326 Bit**. „Ungefähr 150 Bit generische Sicherheit“ ist
vertretbar. „Mindestens 150 Bit“ oder „strikt 150 Bit“ wäre falsch. Falls ein
externes Anforderungsprofil eine harte Untergrenze von 150,000 Bit inklusive
Konstanten fordert, erfüllt dieser Parametersatz sie nicht; der technische
Eignungsentscheid dieses Berichts verwendet ausdrücklich die ehrliche
„ungefähr 150 Bit“-Formulierung.

## 11. Basispunkt, Kodierung und A24-Konvention

Der Basispunkt wird nicht als unbegründete Konstante eingeführt. Die
deterministische Ableitung in
[derive_c44730_basepoint.py](../scripts/derive_c44730_basepoint.py) verwendet

```text
DST = "ED301-BASEPOINT-DERIVATION-v1"
input = DST || I2OSP(counter, 4, big-endian)
SHAKE256-Ausgabe = 38 Byte
```

Die Bits `301..303` werden gelöscht, das Ergebnis wird little-endian als `y`
interpretiert, `y >= p` verworfen, `x` mit kanonischer LSB `0` rekonstruiert
und anschließend mit dem Cofaktor `4` multipliziert. Der erste zulässige
Zähler ist bereits `0`. Das Ergebnis ist

```text
G.x = 114483960210649758260691970228447544333115946824833551736797985468026643833345600929055
G.y = 3123599847077067352547410063473606051762622289826321814465731066121453938271612909425522539

encode(G) = 6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898
```

Es ist `G != O`, `[q]G = O`; wegen der Primheit von `q` hat `G` exakt Ordnung
`q`. Der vollständige Hash-, Reject-, Cofactor- und Roundtrip-Nachweis steht im
[Python-Rohresultat](../rohresultate/c44730_basepoint_derivation_python.txt).
Eine getrennte PARI-Prüfung bestätigt Punktlage und exakte Ordnung in
[c44730_basepoint_crosscheck_pari.txt](../rohresultate/c44730_basepoint_crosscheck_pari.txt).

Die kanonische Kodierung ist festgelegt als:

- Feldelemente: 38 Byte little-endian, Bits `301..303` müssen null sein;
- Edwards-Punkte: `y` in Bits `0..300`, reservierte Bits `301` und `302` null,
  Bit `303` ist die LSB des kanonischen `x`;
- Skalare: 38 Byte little-endian und strikt `0 <= S < q`;
- strikte externe Punktannahme kann Identität und Torsion verwerfen und die
  Zugehörigkeit zur Primordnungsgruppe verlangen.

Für die Montgomery-Leiter wird eindeutig die Minus-Konvention gewählt:

```text
A24_minus = (A - 2)/4 mod p
           = 1352799263534442616740139614956810975618594433699801520254760472424847496760878864324278092

z_2 = E * (AA + A24_minus * E).
```

`A24_plus = (A+2)/4` ist zwar als Vergleichswert dokumentiert, aber nicht die
Konstante dieser Leiterformel. Diese Entscheidung beseitigt die sonst häufige
Plus/Minus-Mehrdeutigkeit. Das Parameterpaket steht maschinenlesbar in
[ed301-v1.json](../parameter/ed301-v1.json). Die kleine
[Python-Referenz](../referenz/ed301_curve.py) und ihre
[20 bestandenen Tests](../rohresultate/c44730_curve_reference_unittest.txt)
prüfen Edwards-Arithmetik, Kodierung, Modellabbildungen und die x-only-Leiter
gegen die allgemeine Skalarmultiplikation.

## 12. Grenzen des Abschlusses

Dieser Bericht schließt den mathematischen Kurven- und Parameterbefund, nicht
den gesamten Lebenszyklus einer Produktionskryptographie ab:

- Die Python-Referenz arbeitet variabelzeitig und affin. Sie ist ausdrücklich
  **nicht produktionstauglich** und nicht gegen Timing-, Cache-, Fault- oder
  Invalid-Curve-Angriffe gehärtet.
- Es wurde keine produktive Signatur- oder XDH-Implementierung auditiert.
- Es liegt kein externer Kryptoaudit durch eine unabhängige Organisation vor.
- Die Endringleiterbestimmung ist eine begründete Vulkaninferenz; die
  konservative Sicherheitsgrenze deckt die verbleibende Alternative ab.
- Magma-/Primo-Exporte stehen für zusätzliche Reproduktion bereit, sind wegen
  des unabhängigen Python-Punktzeugen-/Hasse-Beweises aber kein offener
  Ordnungsnachweis.

Unter diesen klaren Grenzen ist der technische Befund positiv: `c = 44730`
liefert einen schlüssigen, reproduzierbaren ED301-Kurvenparametersatz mit
twistsicherer Primordnungsstruktur, vollständiger Faktorisierung, formal
belegten Primzahlen, maximalen Einbettungsgraden sowie festgelegtem Basispunkt
und Encoding.

## 13. Zentrale Reproduktionsartefakte

- [Vollständiges PARI-Auditskript](../scripts/audit_c44730_full_reproducibility.gp)
  und [zugehöriges Rohresultat](../rohresultate/audit_c44730_full_reproducibility_pari.txt)
- [Unabhängiger Python-Ordnungsnachweis](../scripts/audit_candidate_c44730_order_witness.py)
  und [Rohresultat](../rohresultate/audit_candidate_c44730_order_witness_python.txt)
- [Sicherheitsparameter-Audit](../scripts/audit_c44730_security_parameters.gp)
  und [Rohresultat](../rohresultate/audit_c44730_security_parameters_pari.txt)
- [Zertifikatsprüfung](../scripts/audit_c44730_prime_certificates.gp)
  und [Rohresultat](../rohresultate/c44730_q_qtwist_primality_security_pari.txt)
- [Deterministische Basispunktableitung](../scripts/derive_c44730_basepoint.py)
  und [Rohresultat](../rohresultate/c44730_basepoint_derivation_python.txt)
- [Maschinenlesbarer Parametersatz](../parameter/ed301-v1.json)
- [Normative Kurvenspezifikation](../spezifikation/ED301-v1.md) und
  [normative Signaturspezifikation](../spezifikation/Ed301-Sig-v1.md)
- [Suchtranskript-Prüfer](../scripts/verify_search_transcript.py) für die
  Minimalität des Auswahlzählers
- [Positive und negative Signaturvektoren](../vektoren/README.md)
- [Unabhängige Node.js-Gegenimplementierung](../gegenpruefung/README.md)
- [Normative X301-v1-Spezifikation](../spezifikation/X301-v1.md),
  [Python-Referenz](../referenz/x301.py) und
  [unabhängige Node-Gegenprüfung](../gegenpruefung/x301/README.md)
- [Gesamtreproduktionsanleitung](../REPRODUKTION.md)
