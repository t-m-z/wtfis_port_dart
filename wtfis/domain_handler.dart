part of 'lookup.dart';

/// Logic handler for domain and hostname inputs
/// (port of `handlers/domain.py`).
///
/// Run it via `lookup()` in `lookup.dart`, which wraps the result in a
/// [LookupResult].
class _DomainHandler extends _BaseHandler {
  final int maxResolutions;

  // Dataset containers
  _VtDomain? vtInfo;
  _Resolutions? resolutions;

  _DomainHandler(String entity, _WtfisConfig config, http.Client client,
      List<LookupError> errors)
      : maxResolutions = config.maxResolutions,
        super(entity, config, client, errors, isIp: false);

  @override
  String get type => 'domain';

  @override
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
        await _enrichIps(ips);
      }
    }

    if (_urlhaus case final c?) urlhaus = await c.enrichDomains([entity]);
    if (_whois case final c?) whois = await c.getWhois(entity);
  }

  @override
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
