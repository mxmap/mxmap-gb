# BA-E-Mail-Sec-UK-DE

## Hinweis

Hinweis: Dieses Projekt basiert auf dem Sourcecode einer Forschungsarbeit, 
welcher in folgendem Github-Repo öffentlich einsehbar ist:
https://github.com/mxmap/secassure2026

## Kurzdarstellung

Im Rahmen einer Bachelorarbeit wurde dieses Messprogramm für die Prüfung von E-Mail-Sicherheitsstandards in DE und UK verwendet und weiterentwickelt.
Es wurde um weitere Tests (z.B. MTA-STS/TLSRPT) und um detailliertere Ausgaben erweitert.
Die Entwicklung bzw. die Erweiterung des Messprogramms beschränkt sich dabei größtenteils auf das Unterverzeichnis *src/security_test* 
Die wichtigsten Änderungen sind im 6. Kapitel der Bacheloarbeit beschrieben.

Einige Tipps sind unter /docs/ vorzufinden

## Ausführung

### E-Mail-Sicherheitsstandards (im root-Verzeichnis dieses Repos ausführen!)
```json
uv run scan <cc> [--verbose]
```

## E-Mail-Provideranalyse (im root-Verzeichnis dieses Repos ausführen!)
```json
uv run classify <cc> [--verbose]
```

## Ergebnisse anzeigen lassen (im root-Verzeichnis dieses Repos ausführen!)
```json
python3 -m http.server              # from the project root
```
Die Ergebnisse lassen sich nun in der Regel unter http://localhost:8000/cards/index.html abrufen