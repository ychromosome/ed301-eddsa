# Reproduktion des technischen ED301-Abschlusses

Stand: 12. Juli 2026

Alle nachstehenden Prüfungen sind read-only. Sie verändern weder die drei
Eingangsdokumente noch Zertifikate, Vektoren oder Rohresultate.

## 1. Geprüfte Umgebung

Der Abschlusslauf wurde auf Fedora 43 mit folgenden Ständen ausgeführt:

```text
PARI/GP 2.17.3
pari-seadata 20090618
Python 3.14.6
Node.js v22.22.2
npm 10.9.7
```

Benötigte Fedora-Pakete für den vollständigen Mathematiklauf:

```sh
sudo dnf install pari-gp pari-seadata python3 nodejs npm
```

Die Node-Gegenimplementierung hat keine npm-Abhängigkeiten. `gmp-ecm` wurde
während der explorativen Faktorisierungsarbeit installiert, ist für die
nachstehenden abgeschlossenen Prüfpfade aber nicht erforderlich.

## 2. Unveränderte Eingangsquellen

Die drei technischen Quellen wurden nicht überschrieben. Ihre SHA-256-Werte
sind zusätzlich in `SOURCE_SHA256SUMS` festgehalten:

```text
bbb1dceb92210b042d62ad0b1cc1371b199dcb3272b9a4bf7066e31cad3c20b5  ED301_Whitepaper_Retrocausal_Compatibility_Edition_v1_1.pdf
dbfcd3d3b0f0b16c3d1e3b674098770e157a205a1a6ed81e5ddb16b40a922d25  EMPFEHLUNGEN_ED301_WHITEPAPER_MATHEMATIK.md
48289acd2044c3743e5f80899018466c269b19217ee28aea09973502d36cef83  BRIEFING_CODEX_ED301_KURVE_UND_SIGNATUR.md
```

## 3. Ein-Befehl-Prüfung

Aus dem Basisverzeichnis:

```sh
cd ed301_technischer_abschluss
./scripts/run_all_checks.sh --quick
```

Der schnelle Lauf prüft:

- die unveränderten Eingangsquellen und den Paketmanifest,
- das gespeicherte Suchtranskript mit allen 355 Workerdateien,
- ECPP-Zertifikate für `p`, `q` und `q_twist` in eigenständiger
  Python-Arithmetik,
- die zusätzlichen N−1/BLS-Beweise für `q` und `q_twist`,
- die gespeicherten Zertifikate nochmals in PARI,
- die Kurven- und Twistordnung mit unabhängigen Primordnungszeugen und
  Hasse-Eindeutigkeit,
- die deterministische Basispunktableitung sowie eine PARI-Gegenprüfung,
- sämtliche Python-Tests,
- die eigenen Node-Tests und alle veröffentlichten Signatur- und
  X301-Vektoren.

Für den vollständigen Neuaufbau der teuren Mathematik:

```sh
./scripts/run_all_checks.sh
```

Dieser Lauf erzeugt darüber hinaus ECPP-Zertifikate im Speicher neu, zählt
Hauptkurve und expliziten Twist je zweimal (`ellsea` und `ellcard`),
faktorisiert die Ordnungen, `q-1`, `q_twist-1` und die
Frobeniusdiskriminante neu und bestimmt Gruppenstruktur, CM-Daten und beide
Einbettungsgrade. Auf dem geprüften Rechner mit 16 Kernen/32 Threads dauerte
dieser Zusatzlauf wenige Minuten; einzelne Faktorisierungszeiten schwanken.

Der vollständige PARI-Lauf muss mit

```text
audit_pass=1
```

enden.

## 4. Einzelne Prüfpfade

### Suchtranskript und Minimalität von `c`

```sh
python3 scripts/verify_search_transcript.py --json
```

Erwartet werden `status: PASS`, lückenlose Abdeckung `0..50687`, kein Treffer
vor `44730` und genau ein Treffer bei `44730`. Der Prüfer wiederholt nicht die
teure Suche, sondern validiert jeden gespeicherten Workerblock, Überlappungen,
Fehlermarker, Prüfzahlen und sämtliche Felder des Treffers. Eine vollständige
Neusuche sollte nur in einer Arbeitskopie erfolgen, weil der ursprüngliche
Orchestrator seine Protokolldateien bestimmungsgemäß neu schreibt.

### Frischer PARI-Gesamtaudit

Aus dem Basisverzeichnis oberhalb dieses Pakets:

```sh
gp -q -f ed301_technischer_abschluss/scripts/audit_c44730_full_reproducibility.gp
```

Das Skript schreibt keine Dateien und vertraut weder gespeicherten
Punktzahlen noch Faktorisierungen.

### Unabhängiger Ordnungsnachweis

```sh
python3 scripts/audit_candidate_c44730_order_witness.py
```

Der Prüfer verwendet nur Python-Integerarithmetik und eine eigenständige
affine Weierstraß-Gruppenarithmetik. Erwartete Endmarke:

```text
independent_order_verification=pass
```

### Formale Primzahlnachweise

```sh
python3 scripts/verify_c44730_ecpp_independent.py zertifikate/p_ecpp_internal.pari
python3 scripts/verify_c44730_ecpp_independent.py zertifikate/c44730_q_ecpp_internal.pari
python3 scripts/verify_c44730_ecpp_independent.py zertifikate/c44730_q_twist_ecpp_internal.pari
python3 scripts/verify_c44730_nminus1_bls_independent.py zertifikate/c44730_q_nminus1_bls_internal.pari
python3 scripts/verify_c44730_nminus1_bls_independent.py zertifikate/c44730_q_twist_nminus1_bls_internal.pari
```

Alle fünf Läufe müssen mit einem gültigen Zertifikatsmarker `=1` enden.

### Referenz, Parametersatz und Vektoren

```sh
python3 -m unittest discover -s tests -v
```

Der Testlauf prüft Kurvenarithmetik, Kodierungen, Modellabbildungen,
Montgomery-Leiter, Parametersatz, Signatur-KeyGen/Sign/Verify, X301-Clamping,
X301-KeyGen/Public/Shared, Framing, Null-/Retryfälle, beide Vektorpakete und
das Suchtranskript. Der eingefrorene Stand umfasst 90 Tests.

### Unabhängige Node-Signaturgegenimplementierung

```sh
cd gegenpruefung
npm test
npm run vectors
```

Erwartet werden 42 eigene Tests, 5 positive Vektoren, 41 korrekt abgelehnte
Verifikationsvektoren, 7 interne Fälle und 330 bestandene Assertions.

### Unabhängige Node-X301-Gegenimplementierung

```sh
cd gegenpruefung/x301
npm test
npm run vectors
```

Erwartet werden 32 eigene Vorabtests, 10 positive Vektoren, 2
Agreement-Paare, 18 API-Negativvektoren, 2 Parser-Negativvektoren, 2 interne
Fälle, je 64 Clamp-/`N_t`-Präbilder und 1068 bestandene Assertions.

## 5. Interpretationsgrenze

Ein erfolgreicher Lauf reproduziert die intern geprüfte Mathematik und die
bytegenaue Übereinstimmung zweier Implementierungen. Er ist kein externer
Kryptoaudit und kein Nachweis von Konstantzeit- oder
Seitenkanalresistenz. Python- und Node-Code bleiben **NOT FOR PRODUCTION**.
