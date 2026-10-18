part of 'lookup.dart';

const _geolocationServices = ['ip2location', 'ipinfo', 'ipwhois'];
const _defaultGeolocationService = 'ipwhois';
const _defaultMaxResolutions = 3;

/// Lookup configuration (port of `wtfis/config.py`).
///
/// All enrichments are enabled; every source without an API key is skipped
/// (IPWhois and IPinfo need no key).
class _WtfisConfig {
  final String vtApiKey;
  final String ip2WhoisApiKey;
  final String ip2LocationApiKey;
  final String shodanApiKey;
  final String greynoiseApiKey;
  final String abuseIpDbApiKey;
  final String urlHausApiKey;

  /// One of [_geolocationServices].
  final String geolocationService;

  /// Maximum number of resolutions to enrich (0..10).
  final int maxResolutions;

  _WtfisConfig({
    String? vtApiKey,
    String? ip2WhoisApiKey,
    String? ip2LocationApiKey,
    String? shodanApiKey,
    String? greynoiseApiKey,
    String? abuseIpDbApiKey,
    String? urlHausApiKey,
    this.geolocationService = _defaultGeolocationService,
    this.maxResolutions = _defaultMaxResolutions,
  })  : vtApiKey = _key(vtApiKey),
        ip2WhoisApiKey = _key(ip2WhoisApiKey),
        ip2LocationApiKey = _key(ip2LocationApiKey),
        shodanApiKey = _key(shodanApiKey),
        greynoiseApiKey = _key(greynoiseApiKey),
        abuseIpDbApiKey = _key(abuseIpDbApiKey),
        urlHausApiKey = _key(urlHausApiKey);

  /// `null` and blank keys mean "not set".
  static String _key(String? k) => k?.trim() ?? '';

  /// Checks the configuration. Instead of throwing, all problems are
  /// returned as [LookupError]s of kind [LookupErrorKind.config].
  List<LookupError> validate() => [
        if (maxResolutions < 0 || maxResolutions > 10)
          _configError('maxResolutions: Maximum value is 10 '
              '(got $maxResolutions)'),
        if (!_geolocationServices.contains(geolocationService))
          _configError('geolocationService: Valid services are: '
              '${_geolocationServices.join(', ')} (got $geolocationService)'),
        if (geolocationService == 'ip2location' && ip2LocationApiKey.isEmpty)
          _configError('ip2LocationApiKey is required for ip2location'),
      ];

  static LookupError _configError(String message) =>
      LookupError(LookupErrorKind.config, 'config', message);

  // Clients

  _VTClient? vtClient(http.Client c, List<LookupError> e) =>
      vtApiKey.isNotEmpty ? _VTClient(vtApiKey, c, e) : null;

  _IpEnricherClient<_IpGeoAsn> geoAsnClient(
          http.Client c, List<LookupError> e) =>
      switch (geolocationService) {
        'ip2location' => _Ip2LocationClient(ip2LocationApiKey, c, e),
        'ipinfo' => _IpInfoClient(c, e),
        _ => _IpWhoisClient(c, e),
      };

  /// IP2Whois is preferred for domains (it does not support IPs);
  /// Virustotal is the fallback.
  _WhoisClient? whoisClient(http.Client c, List<LookupError> e,
      {bool isIp = false}) {
    if (ip2WhoisApiKey.isNotEmpty && !isIp) {
      return _Ip2WhoisClient(ip2WhoisApiKey, c, e);
    }
    if (vtApiKey.isNotEmpty) return _VTClient(vtApiKey, c, e);
    return null;
  }

  _ShodanClient? shodanClient(http.Client c, List<LookupError> e) =>
      shodanApiKey.isNotEmpty
          ? _ShodanClient(shodanApiKey, c, e)
          : null;

  _GreynoiseClient? greynoiseClient(http.Client c, List<LookupError> e) =>
      greynoiseApiKey.isNotEmpty
          ? _GreynoiseClient(greynoiseApiKey, c, e)
          : null;

  _AbuseIpDbClient? abuseIpDbClient(http.Client c, List<LookupError> e) =>
      abuseIpDbApiKey.isNotEmpty
          ? _AbuseIpDbClient(abuseIpDbApiKey, c, e)
          : null;

  _UrlHausClient? urlHausClient(http.Client c, List<LookupError> e) =>
      urlHausApiKey.isNotEmpty
          ? _UrlHausClient(urlHausApiKey, c, e)
          : null;
}
