import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'clients.dart';
import 'config.dart';
import 'exceptions.dart';
import 'models/ip_enrichment.dart';
import 'models/json.dart';
import 'models/virustotal.dart';
import 'models/whois.dart';
import 'utils.dart';

/// Logic handler for domain and hostname inputs
/// (port of `handlers/domain.py` + `handlers/base.py`).
class DomainHandler {
  final String entity;
  final int maxResolutions;

  final VTClient? _vt;
  final IpEnricherClient<IpGeoAsn> _geoasn;
  final WhoisClient? _whois;
  final ShodanClient? _shodan;
  final GreynoiseClient? _greynoise;
  final AbuseIpDbClient? _abuseipdb;
  final UrlHausClient? _urlhaus;

  // Dataset containers
  VtDomain? vtInfo;
  Resolutions? resolutions;
  Map<String, IpGeoAsn> geoasn = {};
  Whois? whois;
  Map<String, ShodanIp> shodan = {};
  Map<String, GreynoiseIp> greynoise = {};
  Map<String, AbuseIpDb> abuseipdb = {};
  Map<String, UrlHaus> urlhaus = {};

  /// Warning messages of sources that failed open.
  final List<String> warnings = [];

  DomainHandler(String entity, WtfisConfig config, http.Client client)
      : entity = refang(entity).trim(),
        maxResolutions = config.maxResolutions,
        _vt = config.vtClient(client),
        _geoasn = config.geoAsnClient(client),
        _whois = config.whoisClient(client),
        _shodan = config.shodanClient(client),
        _greynoise = config.greynoiseClient(client),
        _abuseipdb = config.abuseIpDbClient(client),
        _urlhaus = config.urlHausClient(client);

  /// Runs a fetch. Network/HTTP errors fail open and are recorded as
  /// warnings; data model errors raise a [HandlerException].
  Future<void> _fetch(String clientName, Future<void> Function() fn) async {
    try {
      await fn();
    } on HttpStatusException catch (e) {
      warnings.add('Could not fetch $clientName: $e');
    } on http.ClientException catch (e) {
      warnings.add('Could not fetch $clientName: ${e.message}');
    } on SocketException catch (e) {
      warnings.add('Could not fetch $clientName: ${e.message}');
    } on TimeoutException catch (e) {
      warnings.add('Could not fetch $clientName: $e');
    } on ModelException catch (e) {
      throw HandlerException('Data model validation error: $e');
    } on TypeError catch (e) {
      throw HandlerException('Data model validation error: $e');
    }
  }

  /// Main method that controls what gets fetched.
  Future<void> fetchData() async {
    final vt = _vt;
    if (vt != null) {
      await _fetch(vt.name, () async => vtInfo = await vt.getDomain(entity));
      if (maxResolutions != 0) {
        await _fetch(vt.name,
            () async => resolutions = await vt.getDomainResolutions(entity));
      }

      final res = resolutions;
      if (res != null && res.data.isNotEmpty) {
        final ips = res.ipList(maxResolutions);
        await _fetch(
            _geoasn.name, () async => geoasn = await _geoasn.enrichIps(ips));
        if (_shodan case final c?) {
          await _fetch(c.name, () async => shodan = await c.enrichIps(ips));
        }
        if (_greynoise case final c?) {
          await _fetch(c.name, () async => greynoise = await c.enrichIps(ips));
        }
        if (_abuseipdb case final c?) {
          await _fetch(c.name, () async => abuseipdb = await c.enrichIps(ips));
        }
      }
    }

    if (_urlhaus case final c?) {
      await _fetch(
          c.name, () async => urlhaus = await c.enrichDomains([entity]));
    }

    if (_whois case final c?) {
      await _fetch(c.name, () async => whois = await c.getWhois(entity));
    }
  }

  /// Result as JSON-serializable map.
  Json toJson() {
    final res = resolutions;
    return {
      'entity': entity,
      'type': 'domain',
      'virustotal': vtInfo?.toJson(),
      'urlhaus': urlhaus[entity]?.toJson(),
      'resolutions': res == null
          ? null
          : {
              'total': res.count,
              'data': [
                for (final r in res.data.take(maxResolutions))
                  {
                    'ip': r.ipAddress,
                    'resolved': standardizeTimestamp(r.date),
                    'resolver': r.resolver,
                    'last_analysis_stats':
                        r.ipAddressLastAnalysisStats.toJson(),
                    'geoasn': geoasn[r.ipAddress]?.toJson(),
                    'shodan': shodan[r.ipAddress]?.toJson(),
                    'greynoise': greynoise[r.ipAddress]?.toJson(),
                    'abuseipdb': abuseipdb[r.ipAddress]?.toJson(),
                    'link':
                        'https://www.virustotal.com/gui/ip-address/${r.ipAddress}',
                  },
              ],
            },
      'whois': whois?.toJson(),
      'warnings': warnings,
    };
  }
}
