# ED301 – technischer Abschluss

Stand: 12. Juli 2026

Dieses Verzeichnis ist das reproduzierbare technische Abschlusspaket zu
`ED301-v1`, `Ed301-Sig-v1` und der rohen XDH-Funktion `X301-v1`. Der
mathematische Befund ist positiv; die
ursprüngliche Kurve mit `a = 1` wurde dabei ausdrücklich verworfen und nicht
stillschweigend weiterverwendet.

## Kernergebnis

Der unveränderte symbolische Kern lautet

```text
p = 2^301 - 2^99 + 947
d = 301
```

Die transparente Kandidatenregel

```text
s = 947 + c
a = s^2 mod p
```

liefert als ersten geeigneten Zähler

```text
c = 44730
s = 45677
a = 2086388329
```

Für diesen Parametersatz gilt formal und unabhängig gegengeprüft:

```text
#E(F_p)       = 4 * q
#E_twist(F_p) = 4 * q_twist
```

`p`, `q` und `q_twist` sind bewiesene Primzahlen. Beide Gruppen sind zyklisch,
beide Cofaktoren sind `4`, und beide Einbettungsgrade sind maximal. Der
generische Pollard-rho-Aufwand beträgt je nach verwendeter Konstante
`149,826` beziehungsweise mit Negationsoptimierung `149,326` Bit. Die
zutreffende Kurzform ist daher **ungefähr 150 Bit**, nicht „mindestens 150
Bit“.

X301-v1 verwendet 38-Byte-Secrets mit 298 variablen Clamp-Bits. Seine
bekannte private Auswahlmenge begrenzt den generischen Exponentenangriff auf
ungefähr 149 Bit. Hauptkurven- und Twisteingaben profitieren jeweils vom
bewiesenen Cofaktor `4`; Null-/Unendlich-Ergebnisse sind zwingende Fehler.

## Zentrale Artefakte

- [Abnahmebericht](berichte/TECHNISCHER_ABSCHLUSS.md)
- [Technischer Kurvenbericht](berichte/KURVENBERICHT_ED301.md)
- [Normative Kurvenspezifikation](spezifikation/ED301-v1.md)
- [Maschinenlesbarer Parametersatz](parameter/ed301-v1.json)
- [Normative Signaturspezifikation](spezifikation/Ed301-Sig-v1.md)
- [Normative rohe XDH-Funktion](spezifikation/X301-v1.md)
- [Technische Systemgrenze zur Possession-Engine](spezifikation/TECHNISCHE-SYSTEMGRENZE-v1.md)
- [Whitepaper-Änderungsliste](berichte/WHITEPAPER_1_2_AENDERUNGSLISTE.md)
- [Reproduktionsanleitung](REPRODUKTION.md)
- [Python-Kurvenreferenz](referenz/ed301_curve.py),
  [Signaturreferenz](referenz/ed301_sig.py) und
  [X301-Referenz](referenz/x301.py)
- [Positive und negative Testvektoren](vektoren/README.md)
- [Unabhängige Signatur-Gegenimplementierung](gegenpruefung/README.md) und
  [unabhängige X301-Gegenimplementierung](gegenpruefung/x301/README.md)

Die vollständigen ECPP- und N−1/BLS-Zertifikate liegen unter `zertifikate/`,
die Rechenskripte unter `scripts/` und die unverarbeiteten Werkzeugausgaben
unter `rohresultate/`.

## Reproduktion

Der schnelle, ausschließlich prüfende Lauf verwendet die gespeicherten
Zertifikate und unabhängigen Ordnungszeugen:

```sh
cd ed301_technischer_abschluss
./scripts/run_all_checks.sh --quick
```

Ohne `--quick` werden zusätzlich ECPP-Zertifikate, vier direkte
Punktzählungen, Faktorisierungen, CM-Daten und Einbettungsgrade frisch in
PARI/GP berechnet:

```sh
./scripts/run_all_checks.sh
```

Details, Softwarestände und erwartete Endmarken stehen in
[REPRODUKTION.md](REPRODUKTION.md).

## Geltungsgrenze

Das Paket schließt Kurvenparameter, das allgemeine Signaturprofil und die rohe
X301-v1-XDH-Funktion technisch ab. X301-v1 ist keine KDF und kein
authentisierter Handshake. Ein vollständiges Sitzungs-, Transport- oder
narratives Anwendungsprotokoll bleibt eine gesonderte Schicht.

**NOT FOR PRODUCTION:** Die Referenz- und Gegenimplementierungen sind nicht
konstantzeitlich und nicht extern auditiert. Eine reale Verwendung erfordert
eine gehärtete Implementierung, Seitenkanaltests und unabhängige
kryptographische Begutachtung.
