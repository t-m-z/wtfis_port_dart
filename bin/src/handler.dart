part of 'lookup.dart';

/// Clients and IP enrichment containers shared by the domain and the IP
/// address handler (port of `handlers/base.py`).
///
/// No handler throws: failing sources stay `null`/empty and their errors
/// end up in [errors].
abstract class _BaseHandler {
  /// Normalized input (refanged domain, or canonical IP address).
  final String entity;

  /// Errors of all sources, collected instead of thrown.
  final List<_LookupError> errors;

  final _VTClient? _vt;
  final _IpEnricherClient<_IpGeoAsn> _geoasn;
  final _WhoisClient? _whois;
  final _ShodanClient? _shodan;
  final _GreynoiseClient? _greynoise;
  final _AbuseIpDbClient? _abuseipdb;
  final _UrlHausClient? _urlhaus;

  // IP enrichments, keyed by IP address
  Map<String, _IpGeoAsn> geoasn = {};
  Map<String, _ShodanIp> shodan = {};
  Map<String, _GreynoiseIp> greynoise = {};
  Map<String, _AbuseIpDb> abuseipdb = {};
  Map<String, _UrlHaus> urlhaus = {};
  _Whois? whois;

  _BaseHandler(this.entity, _WtfisConfig config, http.Client client,
      this.errors,
      {required bool isIp})
      : _vt = config.vtClient(client, errors),
        _geoasn = config.geoAsnClient(client, errors),
        _whois = config.whoisClient(client, errors, isIp: isIp),
        _shodan = config.shodanClient(client, errors),
        _greynoise = config.greynoiseClient(client, errors),
        _abuseipdb = config.abuseIpDbClient(client, errors),
        _urlhaus = config.urlHausClient(client, errors);

  /// Value of the entity type in the output (`domain` or `ip`).
  String get type;

  /// Main method that controls what gets fetched.
  Future<void> fetchData();

  /// Collected data as JSON-serializable map (without errors).
  _Json toJson();

  /// Enriches [ips] with Shodan, Greynoise and AbuseIPDB (if enabled).
  Future<void> _enrichIps(List<String> ips) async {
    if (_shodan case final c?) shodan = await c.enrichIps(ips);
    if (_greynoise case final c?) greynoise = await c.enrichIps(ips);
    if (_abuseipdb case final c?) abuseipdb = await c.enrichIps(ips);
  }
}
