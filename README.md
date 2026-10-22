# wtfis – Dart-Port

Dart-Port von [wtfis](https://github.com/t-m-z/wtfis) (Original: [pirxthepilot/wtfis](https://github.com/pirxthepilot/wtfis)),
einem Tool für passive Lookups von Domains, Hostnamen und IP-Adressen (IPv4 und IPv6).

Der Port besteht aus **einer asynchronen Funktion `lookup()`**: Sie nimmt eine Adresse (Domain oder IP)
und die API-Keys entgegen, fragt alle Enrichments ab und liefert ein `Future<LookupResult>`.
Es gibt kein `main`, keine `library`-Direktive und keine `export`-Anweisungen.

```dart
import 'wtfis/lookup.dart';

Future<void> example() async {
  final LookupResult result = await lookup(
    'gist.github.com', // oder z. B. '1.1.1.1', '2606:4700:4700::1111'
    vtApiKey: '...',
    shodanApiKey: '...',
    urlHausApiKey: '...',
  );
  print(result.toText()); // oder result.toJsonString(pretty: true)
  for (final e in result.errors) {
    print('${e.source}: ${e.message}');
  }
}
```

**Es werden keine Exceptions geworfen.** Alle Fehler – ungültige Eingabe, ungültige Konfiguration,
HTTP-Fehler, Netzwerkfehler und API-Daten, die nicht zum erwarteten Modell passen – werden gesammelt
und in `LookupResult.errors` geliefert. Fällt eine Quelle aus, ist ihr Eintrag `null`, alle anderen
Quellen werden trotzdem abgefragt.

## Signatur

```dart
Future<LookupResult> lookup(
  String address, {                    // Domain, FQDN, IPv4 oder IPv6
  String? vtApiKey,                    // VirusTotal
  String? ip2WhoisApiKey,              // IP2Whois (Whois für Domains)
  String? ip2LocationApiKey,           // IP2Location (nur mit geolocationService 'ip2location')
  String? shodanApiKey,                // Shodan
  String? greynoiseApiKey,             // Greynoise
  String? abuseIpDbApiKey,             // AbuseIPDB
  String? urlHausApiKey,               // URLhaus
  String geolocationService = 'ipwhois', // 'ipwhois' | 'ipinfo' | 'ip2location'
  int maxResolutions = 3,              // 0..10, nur für Domains
  http.Client? httpClient,             // optional, z. B. für Tests
});
```

* **Alle Enrichments sind aktiv:** Jede Quelle, deren API-Key übergeben wird, wird abgefragt; Quellen ohne
  Key (`null` oder leer) werden übersprungen. Der Geolocation-Dienst wird immer abgefragt
  (IPWhois und IPinfo brauchen keinen Key).
* Defangte Eingaben wie `example[.]com`, `1[.]1[.]1[.]1` oder `2606:4700:4700[:]:1111` werden akzeptiert,
  IPv6 auch in eckigen Klammern. IPv6 wird kanonisch geschrieben
  (`2606:4700:4700:0:0:0:0:1111` → `2606:4700:4700::1111`).
* Nicht-öffentliche IPs (privat, Loopback, Link-Local, Multicast, Dokumentations- und reservierte Bereiche)
  ergeben einen Fehler vom Typ `input`, ebenso eine leere Eingabe.
* `maxResolutions` ist wie im Original nur für Domains gedacht; ein abweichender Wert bei einer IP ist ein
  Fehler vom Typ `config`.

| Quelle | Parameter | Domain | IP |
|---|---|---|---|
| VirusTotal | `vtApiKey` | Domain-Analyse, Resolutions, Whois (Fallback) | IP-Analyse, Whois |
| IP2Whois | `ip2WhoisApiKey` | Whois (bevorzugt) | – |
| IPWhois / IPinfo / IP2Location | `geolocationService`, `ip2LocationApiKey` | Geo/ASN der aufgelösten IPs | Geo/ASN |
| Shodan | `shodanApiKey` | Ports/Dienste der aufgelösten IPs | Ports/Dienste |
| Greynoise | `greynoiseApiKey` | aufgelöste IPs | ✓ |
| AbuseIPDB | `abuseIpDbApiKey` | aufgelöste IPs | ✓ |
| URLhaus | `urlHausApiKey` | Domain-Reputation | IP-Reputation |

## Ergebnis: `LookupResult`

| Member | Bedeutung |
|---|---|
| `entity` | normalisierte Domain bzw. IP-Adresse |
| `type` | `domain` oder `ip` (`null` bei nicht erkennbarer Eingabe) |
| `data` | gesammelte Daten als `Map<String, dynamic>` (siehe Ausgabeformat), `null` bei Abbruch |
| `errors` | `List<LookupError>` |
| `ok` | `true`, wenn kein Fehler aufgetreten ist |
| `aborted` | `true`, wenn der Lookup wegen Eingabe-/Konfigurationsfehler gar nicht lief |
| `httpErrors` | nur die HTTP-Fehler |
| `toJson()` / `toJsonString(pretty: …)` | Ausgabe als Map bzw. JSON |
| `toText(indent: '  ', includeNulls: false)` | lesbarer Text mit Einzügen (siehe unten) |

Ein `LookupError` hat die Felder `kind` (`LookupErrorKind`: `input`, `config`, `http`, `network`, `model`, `internal`),
`source` (z. B. `Virustotal`), `message` und – bei HTTP-Fehlern – `statusCode`, `url` und `body`.
`body` enthält die Antwort des Servers (z. B. eine HTML-Fehlerseite), gekürzt auf 1000 Zeichen.
Aus `url` werden Query-Parameter entfernt, damit API-Keys nicht in der Ausgabe landen.

Antworten, die das Original bewusst ignoriert (Shodan/Greynoise 404 = IP unbekannt, IP2Whois 404/ungültige
Domain), gelten nicht als Fehler.

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

## Textausgabe: `toText()`

`result.toText()` liefert dieselben Daten wie das JSON als lesbaren Text:

* eine Zeile `key: value` pro Feld, verschachtelte Werte mit `indent` eingerückt (Standard: zwei Leerzeichen),
* die Doppelpunkte gleichrangiger Schlüssel eines Abschnitts stehen bündig untereinander
  (der Schlüssel wird mit Leerzeichen aufgefüllt),
* keine geschweiften oder eckigen Klammern,
* Leerzeilen zwischen den Abschnitten (`virustotal`, `urlhaus`, `resolutions`, `whois`, `errors`) und
  zwischen den Einträgen von Listen (Resolutions, URLhaus-URLs, Fehler); Listeneinträge beginnen mit `- `,
* Listen einfacher Werte durch Komma getrennt in einer Zeile, leere Listen und fehlende Abschnitte als `-`,
* Felder ohne Wert (`null` oder leerer Text) unterhalb der obersten Ebene werden weggelassen,
  mit `includeNulls: true` als `-` ausgegeben,
* mehrzeilige Werte (z. B. eine HTML-Fehlerseite) eingerückt unter ihrem Schlüssel.

```
entity: gist.github.com
type  : domain
ok    : true

virustotal:
  id                         : gist.github.com
  type                       : domain
  link                       : https://www.virustotal.com/gui/domain/gist.github.com
  last_analysis_stats        :
    harmless  : 84
    malicious : 0
    suspicious: 0
    timeout   : 0
    undetected: 10
  malicious_vendors          : -
  reputation                 : 0
  popularity_ranks           :
    Majestic      : 532
    Cisco Umbrella: 39463
  categories                 : advice, file sharing/storage, information technology, media sharing, social networks
  …
  last_https_certificate_date: 2022-08-15T22:25:30Z

resolutions:
  total: 37
  data :
    - ip                 : 13.234.210.38
      resolved           : 2022-08-06T14:56:20Z
      resolver           : SecneurX
      …
      shodan             :
        ip          : 13.234.210.38
        …
        services    :
          Other: 22/tcp, 80/tcp, 443/tcp
        last_update : 2022-08-21T07:21:05Z

    - ip                 : 192.30.255.113
      …

whois:
  source      : ip2whois
  domain      : github.com
  registrar   : MarkMonitor, Inc.
  …

errors: -
```

Bei Fehlern:

```
entity     : example.com
type       : domain
ok         : false
virustotal : -
urlhaus    : -
resolutions: -
whois      : -

errors:
  - source     : Virustotal
    type       : http
    message    : 502 Server Error (Bad Gateway)
    status_code: 502
    url        : https://www.virustotal.com/api/v3/domains/example.com
    body       :
      <html>
      <head><title>502 Bad Gateway</title></head>
      …
```

## Aufbau

`wtfis/lookup.dart` enthält alle Imports, die `part`-Direktiven und `lookup()`. Alle übrigen Dateien
beginnen mit `part of` und gehören damit zur selben Bibliothek. Öffentlich sind nur `lookup()` und die
Ergebnistypen `LookupResult`, `LookupError` und `LookupErrorKind`; alles andere trägt ein `_`-Präfix.
Der Ordner `wtfis/` kann als Ganzes in ein anderes Projekt übernommen werden (Abhängigkeit: `package:http`).

```
wtfis/
  lookup.dart         # Imports, part-Direktiven, lookup()
  lookup_result.dart  # part of: LookupResult, LookupError, LookupErrorKind
  handler.dart        # part of: gemeinsame Basis (Clients, IP-Anreicherung)
  domain_handler.dart # part of: Ablauf des Domain-Lookups
  ip_handler.dart     # part of: Ablauf des IP-Lookups
  clients.dart        # part of: API-Clients
  config.dart         # part of: Konfiguration
  exceptions.dart     # part of: _ModelException (nur intern beim Parsen)
  utils.dart          # part of
  models/             # part of '../lookup.dart': Datenmodelle der APIs
test/
  wtfis_test.dart     # testet über lookup()
```

## Tests

```bash
dart pub get
dart test
```

Die Tests verwenden die Fixture-Daten des Originalprojekts (`test/test_data`) und einen gemockten HTTP-Client.

## Unterschiede zum Original

* Keine Kommandozeile: Ergebnis als Objekt (`LookupResult`, auch als JSON) statt Rich-Terminal-Panels.
* API-Keys werden als Parameter übergeben statt aus Umgebungsvariablen / `~/.env.wtfis` gelesen;
  jede Quelle mit Key wird abgefragt (entspricht `--all`).
* Nicht-öffentliche IPs werden als Eingabefehler gemeldet (das Original behandelt sie als Domain).
* Statt der vollständigen `last_analysis_results` wird – wie in der Original-Anzeige – die Liste `malicious_vendors` ausgegeben.

## Lizenz

MIT – siehe [LICENSE](LICENSE) (Copyright des Originals: pirxthepilot).
