import 'package:http/http.dart' as http;

import 'clients.dart';
import 'config.dart';
import 'lookup_result.dart';
import 'models/ip_enrichment.dart';
import 'models/json.dart';
import 'models/virustotal.dart';
import 'models/whois.dart';
import 'utils.dart';

/// Logic handler for domain and hostname inputs
/// (port of `handlers/domain.py` + `handlers/base.py`).
///
/// Run it via `lookup()` in `lookup.dart`, which wraps the result in a
/// [LookupResult].
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

  /// Errors of all sources, collected instead of thrown.
  final List<LookupError> errors;

  DomainHandler(String entity, WtfisConfig config, http.Client client,
      [List<LookupError>? errors])
      : this._(refang(entity).trim(), config, client, errors ?? []);

  DomainHandler._(this.entity, WtfisConfig config, http.Client client,
      this.errors)
      : maxResolutions = config.maxResolutions,
        _vt = config.vtClient(client, errors),
        _geoasn = config.geoAsnClient(client, errors),
        _whois = config.whoisClient(client, errors),
        _shodan = config.shodanClient(client, errors),
        _greynoise = config.greynoiseClient(client, errors),
        _abuseipdb = config.abuseIpDbClient(client, errors),
        _urlhaus = config.urlHausClient(client, errors);

  /// Main method that controls what gets fetched. Never throws: failing
  /// sources stay `null`/empty and their errors end up in [errors].
  Future<void> fetchData() async {
    if (_vt case final vt?) {
      vtInfo = await vt.getDomain(entity);
      if (maxResolutions != 0) {
        resolutions = await vt.getDomainResolutions(entity);
      }

      final res = resolutions;
      if (res != null && res.data.isNotEmpty) {
        final ips = res.ipList(maxResolutions);
        geoasn = await _geoasn.enrichIps(ips);
        if (_shodan case final c?) shodan = await c.enrichIps(ips);
        if (_greynoise case final c?) greynoise = await c.enrichIps(ips);
        if (_abuseipdb case final c?) abuseipdb = await c.enrichIps(ips);
      }
    }

    if (_urlhaus case final c?) urlhaus = await c.enrichDomains([entity]);
    if (_whois case final c?) whois = await c.getWhois(entity);
  }

  /// Collected data as JSON-serializable map (without errors).
  Json toJson() {
    final res = resolutions;
    return {
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
    };
  }
}
