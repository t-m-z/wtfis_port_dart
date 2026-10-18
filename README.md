# wtfis – Dart-Port

Dart-Port von [wtfis](https://github.com/t-m-z/wtfis) (Original: [pirxthepilot/wtfis](https://github.com/pirxthepilot/wtfis)),
einem Tool für passive Domain-/Hostname-Lookups.

Der Port ist eine reine Kommandozeilen-Anwendung – keine Library, keine `export`-Anweisungen.
Kern ist **eine Funktion, die eine Domain entgegennimmt und das Ergebnis als JSON-String liefert**:
`lookupDomain()` in [`bin/src/lookup.dart`](bin/src/lookup.dart).

Da Netzwerkzugriffe in Dart asynchron sind, liefert die Funktion ein `Future<String>`.

## Aufbau

```
bin/
  wtfis.dart            # Einstiegspunkt (CLI)
  src/
    lookup.dart         # lookupDomain()
    domain_handler.dart # Ablauf des Domain-Lookups
    clients.dart        # API-Clients
    config.dart         # WtfisConfig, ~/.env.wtfis
    exceptions.dart
    utils.dart
    models/             # Datenmodelle der APIs
test/
  wtfis_test.dart       # importiert die Dateien direkt aus bin/src/
```

Jede Datei importiert die benötigten Dateien direkt über relative Pfade.

## Signatur

```dart
Future<String> lookupDomain(
  String domain, {
  WtfisConfig? config,      // Standard: WtfisConfig.fromEnvironment()
  http.Client? httpClient,  // optional, z. B. für Tests
  bool pretty = false,      // eingerückte Ausgabe
});
```

* Defangte Eingaben wie `example[.]com` werden akzeptiert.
* Nicht erreichbare Quellen (HTTP-/Netzwerkfehler) brechen nicht ab, sondern landen unter `"warnings"`.
* Liefert eine API Daten, die nicht zum erwarteten Modell passen, wird eine `HandlerException` geworfen.
* IP-Adressen werden mit `ArgumentError` abgelehnt (dieser Port deckt nur Domains ab).

## Datenquellen und Konfiguration

Wie im Original werden API-Keys aus Umgebungsvariablen bzw. `~/.env.wtfis` gelesen
(siehe [`.env.wtfis.example`](.env.wtfis.example)). Quellen ohne Key werden übersprungen.

| Quelle | Variable | Verwendung |
|---|---|---|
| VirusTotal | `VT_API_KEY` | Domain-Analyse, Resolutions, WHOIS (Fallback) |
| IP2Whois | `IP2WHOIS_API_KEY` | WHOIS (bevorzugt) |
| IPWhois / IPinfo / IP2Location | `GEOLOCATION_SERVICE`, `IP2LOCATION_API_KEY` | Geo/ASN der aufgelösten IPs |
| Shodan | `SHODAN_API_KEY` | Ports/Dienste der aufgelösten IPs (`useShodan` / `all`) |
| Greynoise | `GREYNOISE_API_KEY` | (`useGreynoise` / `all`) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | (`useAbuseIpDb` / `all`) |
| URLhaus | `URLHAUS_API_KEY` | Domain-Reputation (`useUrlHaus` / `all`) |

`WTFIS_DEFAULTS` (z. B. `-s -u`) schaltet die entsprechenden Optionen wie im Original um.

Die Konfiguration kann auch direkt übergeben werden:

```dart
// innerhalb von bin/ bzw. test/
final json = await lookupDomain(
  'example.com',
  config: WtfisConfig(vtApiKey: '...', urlHausApiKey: '...', all: true, maxResolutions: 5),
);
```

## Ausgabeformat

```json
{
  "entity": "gist.github.com",
  "type": "domain",
  "virustotal": {
    "id": "gist.github.com",
    "last_analysis_stats": {"harmless": 84, "malicious": 0, "suspicious": 0, "timeout": 0, "undetected": 10},
    "malicious_vendors": [],
    "reputation": 0,
    "popularity_ranks": {"Majestic": 532, "Cisco Umbrella": 39463},
    "categories": ["advice", "file sharing/storage", "..."],
    "creation_date": "2007-10-09T18:20:50Z",
    "...": "..."
  },
  "urlhaus": null,
  "resolutions": {
    "total": 37,
    "data": [
      {
        "ip": "13.234.210.38",
        "resolved": "2022-08-06T14:56:20Z",
        "last_analysis_stats": {"...": 0},
        "geoasn": {"source": "IPWhois", "asn": "16509", "org": "Amazon Data Services India", "city": "Mumbai", "...": "..."},
        "shodan": null,
        "greynoise": null,
        "abuseipdb": null
      }
    ]
  },
  "whois": {"source": "virustotal", "domain": "github.com", "registrar": "MarkMonitor Inc.", "name_servers": ["..."], "...": "..."},
  "warnings": []
}
```

Zeitstempel werden – wie in der Anzeige des Originals – in `YYYY-MM-DDTHH:MM:SSZ` normalisiert.

## Kommandozeile

```bash
dart pub get
dart run bin/wtfis.dart -p gist.github.com
# oder kompiliert:
dart compile exe bin/wtfis.dart -o wtfis
```

Optionen: `-A/--all`, `-s/--use-shodan`, `-g/--use-greynoise`, `-a/--use-abuseipdb`,
`-u/--use-urlhaus`, `-m/--max-resolutions N`, `--geolocation-service`, `-p/--pretty`.

## Tests

```bash
dart test
```

Die Tests verwenden die Fixture-Daten des Originalprojekts (`test/test_data`) und einen gemockten HTTP-Client.

## Unterschiede zum Original

* Ausgabe als JSON statt Rich-Terminal-Panels; nur Domain-/FQDN-Lookups.
* Statt der vollständigen `last_analysis_results` wird – wie in der Original-Anzeige – die Liste `malicious_vendors` ausgegeben.

## Lizenz

MIT – siehe [LICENSE](LICENSE) (Copyright des Originals: pirxthepilot).
