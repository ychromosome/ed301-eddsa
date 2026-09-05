# Unabhängige Node.js-Gegenprüfung von X301-v1

> **NOT FOR PRODUCTION.** Diese JavaScript-`BigInt`-Implementierung dient der
> transparenten technischen Gegenprüfung. Sie ist nicht konstantzeitlich,
> nicht seitenkanalauditiert und nicht als produktiver Kryptografiebaustein
> geeignet.

## Unabhängigkeitsregel

`x301.js` und `test_independent.js` wurden ausschließlich aus folgenden
normativen Quellen neu geschrieben:

- `parameter/ed301-v1.json`
- `spezifikation/ED301-v1.md`
- `spezifikation/X301-v1.md`

Python-Referenzen, Python-Tests und Vektorgeneratoren wurden weder gelesen
noch importiert oder übernommen. Die Gegenimplementierung und 32 eigene Tests
waren vollständig und erfolgreich, bevor X301-Vektor-JSONs als externes
Vergleichsmaterial geöffnet wurden. Dieser Zwischenstand ist mit Zeitpunkt
und SHA-256-Werten in `pre-vector-test-result.json` festgehalten.

## Aufbau

- `x301.js`: eigenständige Feldarithmetik und 301-Runden-Montgomery-Leiter,
  strikte u-Dekodierung, Clamping mit `N_t`-Ablehnung, `X301`, `Public`,
  `Shared` und `KeyGen`.
- `test_independent.js`: eigene Tests zu Masken, allen 64 `N_t`-Präbildern,
  Grenzen, Kodierung, Fehlerpfaden, fester Iterationszahl, Public/Shared und
  separater affiner Weierstraß-Gegenrechnung auf Hauptkurve und Twist.
- `pre-vector-test-result.json`: unveränderlicher Chronologiebeleg des
  erfolgreichen Eigenlaufs vor Sichtung der Vergleichsvektoren.
- `run_vectors.js`: wird ausschließlich für die nachträgliche externe
  Vektorgegenprüfung verwendet.
- `node-countercheck-result.json`: abschließendes maschinenlesbares Ergebnis.

Es gibt keine npm-Abhängigkeiten. Testinterne Funktionen werden nur exportiert,
wenn vor dem Laden ausdrücklich `X301_ENABLE_TEST_HOOKS=1` gesetzt wurde.

## Reproduktion

Geprüfte Laufzeit: Node.js `v22.22.2` unter Fedora 43.

```bash
cd ed301_technischer_abschluss/gegenpruefung/x301
npm test
npm run vectors
node --check x301.js
node --check test_independent.js
node --check run_vectors.js
```

Der unabhängige Vorabtest vom 12. Juli 2026 endete mit **32 bestanden, 0
fehlgeschlagen**. Die Implementierungs- und Testdateien blieben danach
unverändert.

Die erst anschließend gelesene, final eingefrorene Vektorsammlung ergab:

- positive Funktionsvektoren: **10 von 10**;
- Shared-Agreement-Paare: **2 von 2**;
- negative API-Vektoren: **18 von 18**;
- negative äußere Parser-Vektoren: **2 von 2**;
- interne KeyGen-/All-zero-Vektoren: **2 von 2**;
- alle 64 gemeinsamen Clamp-Präbilder und alle 64 ausgeschlossenen
  `N_t`-Präbilder korrekt behandelt;
- **1068 Assertions**, alle bestanden.

Damit stimmen die unabhängig geschriebene Node-Implementierung und die
veröffentlichten Konformitätsvektoren einschließlich der projektiven
Leiter-Endwerte byte- und integergenau überein. Das ersetzt keinen externen
Produktionsaudit.

