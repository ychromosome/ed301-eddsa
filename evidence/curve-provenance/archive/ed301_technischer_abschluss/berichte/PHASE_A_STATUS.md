# Phase A – Abschlussstatus

Stand: 12. Juli 2026

## Ergebnis

Phase A ist abgeschlossen. Es besteht kein offener Ressourcen- oder
Mathematikpunkt.

Der Ausgangskandidat `a = 1` ist für das beabsichtigte einfache
Primuntergruppenprofil ungeeignet. Seine größten Primfaktoren besitzen nur 221
Bit auf der Hauptkurve und 182 Bit auf dem Twist. Deshalb wurde das
Signaturprofil auf diesem Parametersatz nicht normiert.

Nach ausdrücklicher Autorenentscheidung blieben `p`, `d` sowie die Werte
`301`, `99` und `947` erhalten. Geändert wurde ausschließlich `a` nach der
veröffentlichten Regel

```text
s = 947 + c
a = s^2 mod p.
```

Der kleinste passende Zähler ist nach lückenloser Prüfung `c = 44730`, also
`s = 45677` und `a = 2086388329`.

## Nachgewiesene Hauptwerte

```text
p = 4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011

N = 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612
  = 4 * q

q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403

N_twist = 4074071952668972172536891376818756322102936785292475840710068942732788076946225991873048412
        = 4 * q_twist

q_twist = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103
```

Für `p`, `q` und `q_twist` liegen ECPP-Zertifikate und eigenständige
Python-Verifikationen vor. `q` und `q_twist` besitzen zusätzlich unabhängige
N−1/BLS-Beweise. Die Ordnungen wurden direkt mit SEA berechnet und zusätzlich
durch eigenständige Gruppenarithmetik, Primordnungszeugen und die eindeutige
Vielfachenlage im Hasse-Intervall bewiesen.

Die vollständigen Faktorisierungen, Trace-, Hasse-, Twist-, MOV-, CM-,
Gruppenstruktur- und Sonderfallprüfungen stehen im
[Kurvenbericht](KURVENBERICHT_ED301.md). Die unabhängige zweite
Ordnungsverifikation macht eine Magma-Installation zu einer optionalen
Zusatzprüfung, nicht zu einem offenen Pflichtpunkt.

## Eignungsurteil

- `ED301-v1`: mathematisch geeignet für das definierte strikte
  Primuntergruppenprofil.
- `Ed301-Sig-v1`: technisch vollständig spezifiziert und intern durch zwei
  unabhängig geschriebene Implementierungen gegengeprüft.
- `X301-v1`: als strikt kodierte rohe XDH-Funktion vollständig spezifiziert,
  mit Python-Referenz, positiven/negativen Vektoren und unabhängiger
  Node-Gegenimplementierung bestätigt. KDF und authentisierter Handshake sind
  bewusst gesonderte Protokollschichten.
- Produktionsfreigabe: ausdrücklich nicht erteilt.
