# wtfis – Dart-Port

Dart-Port von [wtfis](https://github.com/t-m-z/wtfis) (Original: [pirxthepilot/wtfis](https://github.com/pirxthepilot/wtfis)),
einem Tool für passive Lookups von Domains, Hostnamen und IP-Adressen (IPv4 und IPv6).

Der Port ist eine reine Kommandozeilen-Anwendung – keine `library`-Direktive, keine `export`-Anweisungen.
**Nach außen sichtbar ist nur eine Funktion: `lookup()`** in [`bin/src/lookup.dart`](bin/src/lookup.dart).
Sie nimmt eine Domain oder IP-Adresse entgegen und liefert ein Ergebnisobjekt, das sich mit `toJsonString()` als JSON ausgeben lässt.

```dart
import 'src/lookup.dart'; // aus bin/ heraus

Future<void> main() async {
  final result = await lookup('gist.github.com', useShodan: true);
  print(result.toJsonString(pretty: true));
  if (!result.ok) print('${result.errors.length} Fehler');
}
```

Da Netzwerkzugriffe in Dart asynchron sind, liefert `lookup()` ein `Future`.

**Es werden keine Exceptions geworfen.** Alle Fehler – ungültige Eingabe, ungültige Konfiguration,
HTTP-Fehler, Netzwerkfehler und API-Daten, die nicht zum erwarteten Modell passen – werden gesammelt
und unter `"errors"` ausgegeben. Fällt eine Quelle aus, ist ihr Eintrag `null`, alle anderen Quellen
werden trotzdem abgefragt.

## Aufbau

`bin/src/lookup.dart` enthält alle Imports, die `part`-Direktiven und `lookup()`. Alle übrigen Dateien
beginnen mit `part of` und gehören damit zur selben Bibliothek. Dart regelt Sichtbarkeit pro Bibliothek:
Alle Klassen, Funktionen und Konstanten außer `lookup()` tragen ein `_`-Präfix. Sie sind in allen Teilen
nutzbar, von außen aber unsichtbar – auch für `bin/wtfis.dart` und die Tests.

```
bin/
  wtfis.dart            # Einstiegspunkt (CLI), importiert nur src/lookup.dart
  src/
    lookup.dart         # Imports, part-Direktiven, lookup()
    lookup_result.dart  # part of: _LookupResult, _LookupError (Ausgabeklassen)
    handler.dart        # part of: gemeinsame Basis (Clients, IP-Anreicherung)
    domain_handler.dart # part of: Ablauf des Domain-Lookups
    ip_handler.dart     # part of: Ablauf des IP-Lookups
    clients.dart        # part of: API-Clients
    config.dart         # part of: Konfiguration, ~/.env.wtfis
    exceptions.dart     # part of: _ModelException (nur intern beim Parsen)
    utils.dart          # part of
    models/             # part of '../lookup.dart': Datenmodelle der APIs
test/
  wtfis_test.dart       # testet ausschließlich über lookup()
```

## Signatur

```dart
Future<_LookupResult> lookup(
  String input, {                  // Domain, FQDN, IPv4 oder IPv6
  bool all = false,                  // -A
  bool useShodan = false,            // -s
  bool useGreynoise = false,         // -g
  bool useAbuseIpDb = false,         // -a
  bool useUrlHaus = false,           // -u
  int maxResolutions = 3,            // -m, 0..10, nur für Domains
  String? geolocationService,        // ip2location | ipinfo | ipwhois (Standard)
  Map<String, String>? environment,  // Standard: Prozess-Umgebung
  String? envFile,                   // Standard: ~/.env.wtfis
  http.Client? httpClient,           // optional, z. B. für Tests
});
```

* Defangte Eingaben wie `example[.]com` werden akzeptiert.
* Öffentliche IPv4- und IPv6-Adressen werden als IP abgefragt, auch defangt (`1[.]1[.]1[.]1`,
  `2606:4700:4700[:]:1111`) oder in eckigen Klammern. IPv6 wird kanonisch geschrieben
  (`2606:4700:4700:0:0:0:0:1111` → `2606:4700:4700::1111`).
* Nicht-öffentliche IPs (privat, Loopback, Link-Local, Multicast, Dokumentations- und reservierte Bereiche)
  ergeben einen Fehler vom Typ `input`, ebenso eine leere Eingabe.
* `maxResolutions` ist wie im Original nur für Domains gedacht; ein abweichender Wert bei einer IP ist ein
  Fehler vom Typ `config`.
* Der Ergebnistyp ist privat. Man kann ihn nicht beim Namen nennen, aber über `final`/`var` normal verwenden.

## Ergebnisobjekt

| Member | Bedeutung |
|---|---|
| `entity` | normalisierte Domain bzw. IP-Adresse |
| `type` | `domain` oder `ip` (`null` bei nicht erkennbarer Eingabe) |
| `data` | gesammelte Daten (`virustotal`, `urlhaus`, `resolutions`, `whois`), `null` bei Abbruch |
| `errors` | Liste der Fehler |
| `ok` | `true`, wenn kein Fehler aufgetreten ist |
| `aborted` | `true`, wenn der Lookup wegen Eingabe-/Konfigurationsfehler gar nicht lief |
| `httpErrors` | nur die HTTP-Fehler |
| `toJson()` / `toJsonString(pretty: …)` | Ausgabe als Map bzw. JSON |

Ein Fehler hat die Felder `kind` (`input`, `config`, `http`, `network`, `model`, `internal`),
`source` (z. B. `Virustotal`), `message` und – bei HTTP-Fehlern – `statusCode`, `url` und `body`.
`body` enthält die Antwort des Servers (z. B. eine HTML-Fehlerseite), gekürzt auf 1000 Zeichen.
Aus `url` werden Query-Parameter entfernt, damit API-Keys nicht in der Ausgabe landen.

Antworten, die das Original bewusst ignoriert (Shodan/Greynoise 404 = IP unbekannt, IP2Whois 404/ungültige
Domain), gelten nicht als Fehler.

## Datenquellen und Konfiguration

Wie im Original werden API-Keys aus Umgebungsvariablen bzw. `~/.env.wtfis` gelesen
(siehe [`.env.wtfis.example`](.env.wtfis.example)). Quellen ohne Key werden übersprungen.

| Quelle | Variable | Verwendung |
|---|---|---|
| VirusTotal | `VT_API_KEY` | Domain-/IP-Analyse, Resolutions, WHOIS (Fallback, für IPs immer) |
| IP2Whois | `IP2WHOIS_API_KEY` | WHOIS für Domains (bevorzugt) |
| IPWhois / IPinfo / IP2Location | `GEOLOCATION_SERVICE`, `IP2LOCATION_API_KEY` | Geo/ASN der IP bzw. der aufgelösten IPs |
| Shodan | `SHODAN_API_KEY` | Ports/Dienste der IP bzw. der aufgelösten IPs (`useShodan` / `all`) |
| Greynoise | `GREYNOISE_API_KEY` | (`useGreynoise` / `all`) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | (`useAbuseIpDb` / `all`) |
| URLhaus | `URLHAUS_API_KEY` | Domain-/IP-Reputation (`useUrlHaus` / `all`) |

`WTFIS_DEFAULTS` (z. B. `-s -u`) schaltet die entsprechenden Optionen wie im Original um.

Statt über die Umgebung können API-Keys auch über `environment` übergeben werden:

```dart
final result = await lookup(
  'example.com',
  environment: {'VT_API_KEY': '...', 'URLHAUS_API_KEY': '...'},
  all: true,
  maxResolutions: 5,
);
```

## Ausgabeformat

### Domain

```json
{
  "entity": "gist.github.com",
  "type": "domain",
  "ok": false,
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
  "errors": [
    {
      "source": "Shodan",
      "type": "http",
      "message": "502 Server Error (Bad Gateway)",
      "status_code": 502,
      "url": "https://api.shodan.io/shodan/host/13.234.210.38",
      "body": "<html><head><title>502 Bad Gateway</title>…"
    }
  ]
}
```

### IP-Adresse

```json
{
  "entity": "1.1.1.1",
  "type": "ip",
  "ok": true,
  "virustotal": {
    "id": "1.1.1.1",
    "type": "ip_address",
    "link": "https://www.virustotal.com/gui/ip-address/1.1.1.1",
    "last_analysis_stats": {"...": 0},
    "malicious_vendors": [],
    "reputation": 134,
    "asn": "13335",
    "as_owner": "CLOUDFLARENET",
    "network": "1.1.1.0/24",
    "...": "..."
  },
  "geoasn": {"source": "IPWhois", "ip": "1.1.1.1", "city": "Sydney", "...": "..."},
  "shodan": {"ip": "1.1.1.1", "services": {"Other": ["53/tcp", "53/udp", "..."], "...": "..."}, "...": "..."},
  "greynoise": {"ip": "1.1.1.1", "riot": true, "classification": "benign", "...": "..."},
  "abuseipdb": {"ip_address": "1.1.1.1", "abuse_confidence_score": 100, "...": "..."},
  "urlhaus": {"host": "1.1.1.1", "...": "..."},
  "whois": {"source": "virustotal", "...": "..."},
  "errors": []
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

Das JSON wird immer ausgegeben, auch wenn Fehler aufgetreten sind; die Fehler stehen zusätzlich
auf stderr. Exit-Codes: `0` ohne Fehler, `1` wenn einzelne Quellen fehlgeschlagen sind,
`64` bei falscher Bedienung, ungültiger Eingabe oder Konfiguration.

## Tests

```bash
dart test
```

Die Tests verwenden die Fixture-Daten des Originalprojekts (`test/test_data`) und einen gemockten HTTP-Client.
Sie greifen nur auf `lookup()` zu; Modelle und Hilfsfunktionen werden über dessen Ergebnis geprüft.

## Unterschiede zum Original

* Ausgabe als JSON statt Rich-Terminal-Panels.
* Nicht-öffentliche IPs werden als Eingabefehler gemeldet (das Original behandelt sie als Domain).
* Statt der vollständigen `last_analysis_results` wird – wie in der Original-Anzeige – die Liste `malicious_vendors` ausgegeben.

## Lizenz

MIT – siehe [LICENSE](LICENSE) (Copyright des Originals: pirxthepilot).
