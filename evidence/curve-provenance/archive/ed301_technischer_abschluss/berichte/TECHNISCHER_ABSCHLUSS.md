# Technischer Abschluss ED301-v1, Ed301-Sig-v1 und X301-v1

Stand: 12. Juli 2026

## 1. Abnahmeentscheidung

Die im technischen Briefing definierten Abnahmekriterien für die Kurve
`ED301-v1` und das allgemeine Signaturverfahren `Ed301-Sig-v1` sind erfüllt.
Die anschließend beauftragte rohe XDH-Funktion `X301-v1` ist ebenfalls
bytegenau spezifiziert und unabhängig gegengeprüft.
Es besteht kein offener mathematischer oder implementatorischer
Spezifikationspunkt innerhalb dieses Auftrags.

Die Entscheidung ist kein nachträgliches Gutheißen des Whitepaper-Entwurfs
1.1: Dessen Ausgangskurve mit `a=1` ist ungeeignet. Der abgeschlossene
Parametersatz verwendet nach ausdrücklicher Autorenentscheidung die
transparente Ersatzregel und ihren ersten geeigneten Zähler:

```text
c = 44730
s = 947 + c = 45677
a = s^2 mod p = 2086388329
d = 301
p = 2^301 - 2^99 + 947
```

Die Werte `301`, `99` und `947` bleiben damit in ihren festgelegten Rollen
erhalten.

## 2. Abnahmematrix

| Kriterium | Ergebnis | Zentraler Beleg |
|---|---|---|
| formale Primheit von `p` | bestanden | ECPP-Zertifikat und eigenständiger Python-Prüfer |
| exakte Hauptkurvenordnung | `N=4q` | direkte SEA-/`ellcard`-Zählung und unabhängiger Ordnungszeuge |
| exakte Twistordnung | `N_t=4q_t` | explizites Twistmodell, direkte Zählung und unabhängiger Ordnungszeuge |
| vollständige Faktorisierung | bestanden | `N`, `N_t`, `q-1`, `q_t-1` und Frobeniusdiskriminante |
| Primheit von `q`, `q_t` | bestanden | ECPP sowie zusätzliche N−1/BLS-Beweise |
| Hasse-, Trace- und Twistrelation | bestanden | `N+N_t=2p+2`, `t^2<=4p` |
| Gruppenstruktur | bestanden | beide Gruppen zyklisch, beide Cofaktoren `4` |
| MOV-/Einbettungsgradprüfung | bestanden | `ord_q(p)=q-1`, `ord_q_t(p)=q_t-1` |
| CM-/Sonderstrukturprüfung | bestanden | gewöhnlich, nicht anomal, `j!=0,1728`, konservative Endringbewertung |
| transparente Parameterauswahl | bestanden | 355 Workerdateien, lückenlos `c=0..50687`, erster Treffer `44730` |
| Basispunkt exakter Ordnung `q` | bestanden | deterministische Ableitung, Python- und PARI-Prüfung |
| bitgenaue Kurvennorm | bestanden | `spezifikation/ED301-v1.md` und `parameter/ed301-v1.json` |
| bitgenaue Signaturnorm | bestanden | `spezifikation/Ed301-Sig-v1.md` |
| bitgenaue rohe XDH-Norm | bestanden | `spezifikation/X301-v1.md` |
| Referenzimplementierungen | bestanden | Python für Kurve, Signatur und X301; ausdrücklich nicht produktionsreif |
| Signaturvektoren | bestanden | 5 positiv, 41 Verify-negativ, 7 interne Fälle |
| X301-Vektoren | bestanden | 10 positiv, 18 API-negativ, 2 Parser-negativ, 2 intern |
| unabhängige Signatur-Gegenimplementierung | bestanden | Node.js/BigInt, 42 eigene Tests und 330 Vektorassertionen |
| unabhängige X301-Gegenimplementierung | bestanden | Node.js/BigInt, 32 eigene Tests und 1068 Vektorassertionen |
| Whitepaper-Änderungsliste | bestanden | konkrete Fundstellen und Aktionen für Version 1.2 |

## 3. Mathematisches Endergebnis

```text
N = 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612
  = 4 * q

q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403

N_t = 4074071952668972172536891376818756322102936785292475840710068942732788076946225991873048412
    = 4 * q_t

q_t = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103
```

`p`, `q` und `q_t` sind formal prim. Die Standarderwartung für Pollard rho
liegt bei `149,825748...` Bit; bei idealer Ausnutzung der Negationsabbildung
bei `149,325748...` Bit. Die freigegebene Formulierung lautet deshalb
**ungefähr 150 Bit generische klassische Sicherheit**. Eine Behauptung
„mindestens 150 Bit“ ist nicht freigegeben.

X301-v1 besitzt nach dem Clamping `2^298-1` zulässige geklampte Skalare.
Damit beträgt die generische Sicherheit gegen einen Angriff auf die bekannte
private Auswahlmenge ungefähr 149 Bit. Der einzige im ursprünglichen
Clamp-Bereich liegende annihilierende Twist-Skalar `k=N_t` wird ausdrücklich
verworfen; `KeyGen` zieht in diesem Fall neu.

## 4. Letzte Wiederholungsprüfung

Am 12. Juli 2026 wurde der eingefrorene Stand nochmals geprüft:

- frischer PARI-Gesamtaudit einschließlich vier Punktzählungen,
  ECPP-Neuerzeugung, Faktorisierungen, CM und Einbettungsgraden:
  `audit_pass=1`;
- unabhängige ECPP-Prüfung von `p`, `q` und `q_t`: jeweils gültig;
- unabhängige N−1/BLS-Prüfung von `q` und `q_t`: jeweils gültig;
- unabhängiger Ordnungsnachweis für Kurve und Twist: bestanden;
- gespeichertes Suchtranskript: 355/355 Workerdateien gültig;
- Python-Gesamttests einschließlich X301 und beider Vektorpakete: 90/90
  bestanden;
- Signatur-Node-Gegenprüfung: 42/42 eigene Tests und 330/330
  Vektorassertionen;
- positive Vektoren: 5/5; negative Verify-Vektoren: 41/41 abgelehnt;
  interne Framing-/Null-/Retryfälle: 7/7;
- X301-Node-Gegenprüfung: 32/32 eigene Vorabtests und 1068/1068
  Vektorassertionen;
- X301-Vektoren: 10/10 positiv, 2/2 Agreement-Paare, 18/18 API-negativ,
  2/2 Parser-negativ und 2/2 interne Fälle.

Der vollständige wiederholbare Ablauf steht in
[REPRODUKTION.md](../REPRODUKTION.md). Die Hashlisten `SOURCE_SHA256SUMS` und
`SHA256SUMS` fixieren Eingangsquellen und Abschlusspaket.

## 5. Bewusste Grenzen

X301-v1 ist die vollständige rohe XDH-Funktion, aber noch keine KDF und kein
authentisierter Handshake. Der Abschluss umfasst daher kein vollständiges
Sitzungs-, Anwendungs-, Identitäts- oder narratives Protokoll. `context` und
`message` bleiben opake Bytefolgen. Die genaue Trennlinie steht in der
[technischen Systemgrenze](../spezifikation/TECHNISCHE-SYSTEMGRENZE-v1.md).

Ebenso ist dies keine Produktionsfreigabe. Die Python-Referenz und die
Node-Gegenimplementierung sind variabelzeitig und nicht gegen Timing-, Cache-,
Fault- oder andere Seitenkanalangriffe gehärtet. Reale Verwendung setzt eine
konstantzeitliche Implementierung, unabhängige externe Kryptobegutachtung,
Seitenkanaltests und sichere Integration voraus.
