part of 'lookup.dart';

/// Logic handler for IPv4 and IPv6 address inputs (port of
/// `handlers/ip.py`).
///
/// [entity] is the canonical form of a public IP address (see
/// `lookup()`).
class _IpAddressHandler extends _BaseHandler {
  _VtIpAddress? vtInfo;

  _IpAddressHandler(String entity, _WtfisConfig config, http.Client client,
      List<LookupError> errors)
      : super(entity, config, client, errors, isIp: true);

  @override
  String get type => 'ip';

  @override
  Future<void> fetchData() async {
    final ips = [entity];
    geoasn = await _geoasn.enrichIps(ips);
    if (_vt case final vt?) vtInfo = await vt.getIpAddress(entity);
    if (_shodan case final c?) shodan = await c.enrichIps(ips);
    if (_urlhaus case final c?) urlhaus = await c.enrichIps(ips);
    if (_greynoise case final c?) greynoise = await c.enrichIps(ips);
    if (_abuseipdb case final c?) abuseipdb = await c.enrichIps(ips);
    if (_whois case final c?) whois = await c.getWhois(entity);
  }

  /// The enrichment for [entity]. Only one IP is queried, so a result the
  /// API keyed differently (e.g. another IPv6 notation) is used as well.
  T? _single<T>(Map<String, T> m) => m[entity] ?? m.values.firstOrNull;

  @override
  _Json toJson() => {
        'virustotal': vtInfo?.toJson(),
        'geoasn': _single(geoasn)?.toJson(),
        'shodan': _single(shodan)?.toJson(),
        'greynoise': _single(greynoise)?.toJson(),
        'abuseipdb': _single(abuseipdb)?.toJson(),
        'urlhaus': _single(urlhaus)?.toJson(),
        'whois': whois?.toJson(),
      };
}
