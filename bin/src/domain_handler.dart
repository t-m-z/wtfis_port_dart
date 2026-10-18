part of 'lookup.dart';

/// Logic handler for domain and hostname inputs
/// (port of `handlers/domain.py` + `handlers/base.py`).
///
/// Run it via `lookup()` in `lookup.dart`, which wraps the result in a
/// [_LookupResult].
class _DomainHandler {
  final String entity;
  final int maxResolutions;

  final _VTClient? _vt;
  final _IpEnricherClient<_IpGeoAsn> _geoasn;
  final _WhoisClient? _whois;
  final _ShodanClient? _shodan;
  final _GreynoiseClient? _greynoise;
  final _AbuseIpDbClient? _abuseipdb;
  final _UrlHausClient? _urlhaus;

  // Dataset containers
  _VtDomain? vtInfo;
  _Resolutions? resolutions;
  Map<String, _IpGeoAsn> geoasn = {};
  _Whois? whois;
  Map<String, _ShodanIp> shodan = {};
  Map<String, _GreynoiseIp> greynoise = {};
  Map<String, _AbuseIpDb> abuseipdb = {};
  Map<String, _UrlHaus> urlhaus = {};

  /// Errors of all sources, collected instead of thrown.
  final List<_LookupError> errors;

  _DomainHandler(String entity, _WtfisConfig config, http.Client client,
      [List<_LookupError>? errors])
      : this._(_refang(entity).trim(), config, client, errors ?? []);

  _DomainHandler._(this.entity, _WtfisConfig config, http.Client client,
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
  _Json toJson() {
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
                    'resolved': _standardizeTimestamp(r.date),
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
