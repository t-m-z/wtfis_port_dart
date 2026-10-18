part of 'lookup.dart';

const _abuseIpDbApiKeyVar = 'ABUSEIPDB_API_KEY';
const _greynoiseApiKeyVar = 'GREYNOISE_API_KEY';
const _ip2LocationApiKeyVar = 'IP2LOCATION_API_KEY';
const _ip2WhoisApiKeyVar = 'IP2WHOIS_API_KEY';
const _shodanApiKeyVar = 'SHODAN_API_KEY';
const _urlHausApiKeyVar = 'URLHAUS_API_KEY';
const _vtApiKeyVar = 'VT_API_KEY';
const _wtfisDefaultsVar = 'WTFIS_DEFAULTS';
const _geolocationServiceVar = 'GEOLOCATION_SERVICE';

const _geolocationServices = ['ip2location', 'ipinfo', 'ipwhois'];
const _defaultGeolocationService = 'ipwhois';
const _defaultMaxResolutions = 3;

/// Lookup configuration (port of `wtfis/config.py`).
///
/// API keys are optional; every source without a key is skipped.
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

  final bool all;
  final bool useShodan;
  final bool useGreynoise;
  final bool useAbuseIpDb;
  final bool useUrlHaus;

  /// Maximum number of resolutions to enrich (0..10).
  final int maxResolutions;

  _WtfisConfig({
    this.vtApiKey = '',
    this.ip2WhoisApiKey = '',
    this.ip2LocationApiKey = '',
    this.shodanApiKey = '',
    this.greynoiseApiKey = '',
    this.abuseIpDbApiKey = '',
    this.urlHausApiKey = '',
    this.geolocationService = _defaultGeolocationService,
    this.all = false,
    this.useShodan = false,
    this.useGreynoise = false,
    this.useAbuseIpDb = false,
    this.useUrlHaus = false,
    this.maxResolutions = _defaultMaxResolutions,
  });

  /// Checks the configuration. Instead of throwing, all problems are
  /// returned as [_LookupError]s of kind [_LookupErrorKind.config].
  List<_LookupError> validate() => [
        if (maxResolutions < 0 || maxResolutions > 10)
          _configError('maxResolutions: Maximum value is 10 '
              '(got $maxResolutions)'),
        if (!_geolocationServices.contains(geolocationService))
          _configError('geolocationService: Valid services are: '
              '${_geolocationServices.join(', ')} (got $geolocationService)'),
        if (geolocationService == 'ip2location' && ip2LocationApiKey.isEmpty)
          _configError('$_ip2LocationApiKeyVar is not set'),
      ];

  static _LookupError _configError(String message) =>
      _LookupError(_LookupErrorKind.config, 'config', message);

  /// Builds the config from environment variables and `~/.env.wtfis`
  /// (variables already set in the environment take precedence).
  ///
  /// Boolean options set explicitly here are toggled by `WTFIS_DEFAULTS`,
  /// exactly like the command line flags in the original tool.
  factory _WtfisConfig.fromEnvironment({
    Map<String, String>? environment,
    String? envFile,
    bool all = false,
    bool useShodan = false,
    bool useGreynoise = false,
    bool useAbuseIpDb = false,
    bool useUrlHaus = false,
    int maxResolutions = _defaultMaxResolutions,
    String? geolocationService,
  }) {
    final env = {
      ...loadEnvFile(envFile ?? _defaultEnvFile()),
      ...(environment ?? Platform.environment),
    };

    for (final option in (env[_wtfisDefaultsVar] ?? '').split(' ')) {
      switch (option) {
        case '-A' || '--all':
          all = !all;
        case '-s' || '--use-shodan':
          useShodan = !useShodan;
        case '-g' || '--use-greynoise':
          useGreynoise = !useGreynoise;
        case '-a' || '--use-abuseipdb':
          useAbuseIpDb = !useAbuseIpDb;
        case '-u' || '--use-urlhaus':
          useUrlHaus = !useUrlHaus;
      }
    }

    return _WtfisConfig(
      vtApiKey: env[_vtApiKeyVar] ?? '',
      ip2WhoisApiKey: env[_ip2WhoisApiKeyVar] ?? '',
      ip2LocationApiKey: env[_ip2LocationApiKeyVar] ?? '',
      shodanApiKey: env[_shodanApiKeyVar] ?? '',
      greynoiseApiKey: env[_greynoiseApiKeyVar] ?? '',
      abuseIpDbApiKey: env[_abuseIpDbApiKeyVar] ?? '',
      urlHausApiKey: env[_urlHausApiKeyVar] ?? '',
      geolocationService: geolocationService ??
          env[_geolocationServiceVar] ??
          _defaultGeolocationService,
      all: all,
      useShodan: useShodan,
      useGreynoise: useGreynoise,
      useAbuseIpDb: useAbuseIpDb,
      useUrlHaus: useUrlHaus,
      maxResolutions: maxResolutions,
    );
  }

  static String? _defaultEnvFile() {
    final home =
        Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
    return home == null ? null : '$home${Platform.pathSeparator}.env.wtfis';
  }

  // Clients

  _VTClient? vtClient(http.Client c, List<_LookupError> e) =>
      vtApiKey.isNotEmpty ? _VTClient(vtApiKey, c, e) : null;

  _IpEnricherClient<_IpGeoAsn> geoAsnClient(
          http.Client c, List<_LookupError> e) =>
      switch (geolocationService) {
        'ip2location' => _Ip2LocationClient(ip2LocationApiKey, c, e),
        'ipinfo' => _IpInfoClient(c, e),
        _ => _IpWhoisClient(c, e),
      };

  /// IP2Whois is preferred for domains; Virustotal is the fallback.
  _WhoisClient? whoisClient(http.Client c, List<_LookupError> e) {
    if (ip2WhoisApiKey.isNotEmpty) {
      return _Ip2WhoisClient(ip2WhoisApiKey, c, e);
    }
    if (vtApiKey.isNotEmpty) return _VTClient(vtApiKey, c, e);
    return null;
  }

  _ShodanClient? shodanClient(http.Client c, List<_LookupError> e) =>
      (useShodan || all) && shodanApiKey.isNotEmpty
          ? _ShodanClient(shodanApiKey, c, e)
          : null;

  _GreynoiseClient? greynoiseClient(http.Client c, List<_LookupError> e) =>
      (useGreynoise || all) && greynoiseApiKey.isNotEmpty
          ? _GreynoiseClient(greynoiseApiKey, c, e)
          : null;

  _AbuseIpDbClient? abuseIpDbClient(http.Client c, List<_LookupError> e) =>
      (useAbuseIpDb || all) && abuseIpDbApiKey.isNotEmpty
          ? _AbuseIpDbClient(abuseIpDbApiKey, c, e)
          : null;

  _UrlHausClient? urlHausClient(http.Client c, List<_LookupError> e) =>
      (useUrlHaus || all) && urlHausApiKey.isNotEmpty
          ? _UrlHausClient(urlHausApiKey, c, e)
          : null;
}

/// Minimal dotenv parser (`KEY=value`, `#` comments, optional quotes).
Map<String, String> _loadEnvFile(String? path) {
  if (path == null) return {};
  final file = File(path);
  if (!file.existsSync()) return {};
  final result = <String, String>{};
  for (var line in file.readAsLinesSync()) {
    line = line.trim();
    if (line.isEmpty || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.substring(7);
    final idx = line.indexOf('=');
    if (idx <= 0) continue;
    var value = line.substring(idx + 1).trim();
    if (value.length >= 2 &&
        (value[0] == '"' || value[0] == "'") &&
        value[value.length - 1] == value[0]) {
      value = value.substring(1, value.length - 1);
    }
    result[line.substring(0, idx).trim()] = value;
  }
  return result;
}
