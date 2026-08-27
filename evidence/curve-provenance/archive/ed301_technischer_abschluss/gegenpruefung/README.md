# Unabhängige Node.js-Gegenprüfung von ED301

> **NOT FOR PRODUCTION.** Diese BigInt-Implementierung ist eine transparente
> Gegenprüfung, kein seitenkanalresistenter oder produktionsauditierter
> Kryptografiebaustein.

## Unabhängigkeitsregel

`ed301.js` und die eigenen Tests wurden ausschließlich aus diesen beiden
normativen Quellen neu geschrieben:

- `parameter/ed301-v1.json`
- `spezifikation/Ed301-Sig-v1.md`

Die Dateien `referenz/ed301_curve.py`, `referenz/ed301_sig.py` und deren Tests
wurden hierfür weder gelesen noch importiert oder übernommen. Die
Gegenimplementierung und 42 eigene Tests waren fertig und erfolgreich, bevor
die Vektor-JSON-Dateien eingelesen wurden.

Erst danach wurden

- `vektoren/ed301-sig-v1-positive.json` und
- `vektoren/ed301-sig-v1-negative.json`

als externes Vergleichsmaterial ausgeführt. Deren Provenienzmetadaten nennen
auch Python-Dateien; `run_vectors.js` öffnet diese Python-Dateien ausdrücklich
nicht.

## Aufbau

- `ed301.js`: eigene erweiterte projektive Edwards-Arithmetik mit JavaScript
  `BigInt`, strikte kanonische Punkt- und Skalardecoder, KeyGen, Sign, Verify
  sowie gepufferte und echte Chunk-/Ein-Pass-Verarbeitung.
- `test_independent.js`: 42 vor den Vergleichsvektoren entstandene Tests zu
  Kurvenarithmetik, Ableitung, Kodierung, Framing, Streaming, Ablehnungen und
  injizierten Null-/Retry-Fällen.
- `run_vectors.js`: nachträgliche Prüfung sämtlicher veröffentlichter positiver,
  negativer und interner Vektoren einschließlich Zwischenwerten.
- `node-countercheck-result.json`: maschinenlesbares Abnahmeergebnis mit
  SHA-256-Hashes.

SHAKE256 stammt direkt aus `node:crypto`. Es gibt keine npm-Abhängigkeiten.
Testinjektionen sind nur vorhanden, wenn vor dem Laden des Moduls ausdrücklich
`ED301_ENABLE_TEST_HOOKS=1` gesetzt wird; in der normalen API existiert
`__testOnly` nicht.

Die geheime Skalarmultiplikation ist absichtlich einfach und nachvollziehbar,
aber **nicht konstantzeitlich**. Das Modul darf daher nicht als
Produktionsimplementierung eingesetzt werden.

## Reproduktion

Geprüfte Laufzeit: Node.js `v22.22.2` unter Fedora 43.

```bash
cd ed301_technischer_abschluss/gegenpruefung
npm test
npm run vectors
node --check ed301.js
node --check test_independent.js
node --check run_vectors.js
```

Abnahme vom 12. Juli 2026:

- eigene Tests: **42 bestanden, 0 fehlgeschlagen**;
- positive Vergleichsvektoren: **5 von 5**;
- negative Verify-Vektoren: **41 von 41 korrekt abgelehnt**;
- interne Framing-/Null-/Retry-Vektoren: **7 von 7**;
- Assertions des Vektorlaufs: **330**, alle bestanden.

Damit stimmen zwei unabhängig geschriebene Implementierungen auf allen
veröffentlichten Konformitätsvektoren bytegenau überein. Diese Übereinstimmung
ist eine technische Gegenprüfung, ersetzt aber keinen externen
Produktionsaudit.
