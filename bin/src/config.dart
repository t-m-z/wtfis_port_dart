import 'dart:io';

import 'package:http/http.dart' as http;

import 'clients.dart';
import 'models/ip_enrichment.dart';

const abuseIpDbApiKeyVar = 'ABUSEIPDB_API_KEY';
const greynoiseApiKeyVar = 'GREYNOISE_API_KEY';
const ip2LocationApiKeyVar = 'IP2LOCATION_API_KEY';
const ip2WhoisApiKeyVar = 'IP2WHOIS_API_KEY';
const shodanApiKeyVar = 'SHODAN_API_KEY';
const urlHausApiKeyVar = 'URLHAUS_API_KEY';
const vtApiKeyVar = 'VT_API_KEY';
const wtfisDefaultsVar = 'WTFIS_DEFAULTS';
const geolocationServiceVar = 'GEOLOCATION_SERVICE';

const geolocationServices = ['ip2location', 'ipinfo', 'ipwhois'];
const defaultGeolocationService = 'ipwhois';
const defaultMaxResolutions = 3;

/// Lookup configuration (port of `wtfis/config.py`).
///
/// API keys are optional; every source without a key is skipped.
class WtfisConfig {
  final String vtApiKey;
  final String ip2WhoisApiKey;
  final String ip2LocationApiKey;
  final String shodanApiKey;
  final String greynoiseApiKey;
  final String abuseIpDbApiKey;
  final String urlHausApiKey;

  /// One of [geolocationServices].
  final String geolocationService;

  final bool all;
  final bool useShodan;
  final bool useGreynoise;
  final bool useAbuseIpDb;
  final bool useUrlHaus;

  /// Maximum number of resolutions to enrich (0..10).
  final int maxResolutions;

  WtfisConfig({
    this.vtApiKey = '',
    this.ip2WhoisApiKey = '',
    this.ip2LocationApiKey = '',
    this.shodanApiKey = '',
    this.greynoiseApiKey = '',
    this.abuseIpDbApiKey = '',
    this.urlHausApiKey = '',
    this.geolocationService = defaultGeolocationService,
    this.all = false,
    this.useShodan = false,
    this.useGreynoise = false,
    this.useAbuseIpDb = false,
    this.useUrlHaus = false,
    this.maxResolutions = defaultMaxResolutions,
  }) {
    if (maxResolutions < 0 || maxResolutions > 10) {
      throw ArgumentError.value(
          maxResolutions, 'maxResolutions', 'Maximum value is 10');
    }
    if (!geolocationServices.contains(geolocationService)) {
      throw ArgumentError.value(geolocationService, 'geolocationService',
          'Valid services are: ${geolocationServices.join(', ')}');
    }
    if (geolocationService == 'ip2location' && ip2LocationApiKey.isEmpty) {
      throw ArgumentError('$ip2LocationApiKeyVar is not set');
    }
  }

  /// Builds the config from environment variables and `~/.env.wtfis`
  /// (variables already set in the environment take precedence).
  ///
  /// Boolean options set explicitly here are toggled by `WTFIS_DEFAULTS`,
  /// exactly like the command line flags in the original tool.
  factory WtfisConfig.fromEnvironment({
    Map<String, String>? environment,
    String? envFile,
    bool all = false,
    bool useShodan = false,
    bool useGreynoise = false,
    bool useAbuseIpDb = false,
    bool useUrlHaus = false,
    int maxResolutions = defaultMaxResolutions,
    String? geolocationService,
  }) {
    final env = {
      ...loadEnvFile(envFile ?? _defaultEnvFile()),
      ...(environment ?? Platform.environment),
    };

    for (final option in (env[wtfisDefaultsVar] ?? '').split(' ')) {
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

    return WtfisConfig(
      vtApiKey: env[vtApiKeyVar] ?? '',
      ip2WhoisApiKey: env[ip2WhoisApiKeyVar] ?? '',
      ip2LocationApiKey: env[ip2LocationApiKeyVar] ?? '',
      shodanApiKey: env[shodanApiKeyVar] ?? '',
      greynoiseApiKey: env[greynoiseApiKeyVar] ?? '',
      abuseIpDbApiKey: env[abuseIpDbApiKeyVar] ?? '',
      urlHausApiKey: env[urlHausApiKeyVar] ?? '',
      geolocationService: geolocationService ??
          env[geolocationServiceVar] ??
          defaultGeolocationService,
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

  VTClient? vtClient(http.Client c) =>
      vtApiKey.isNotEmpty ? VTClient(vtApiKey, c) : null;

  IpEnricherClient<IpGeoAsn> geoAsnClient(http.Client c) =>
      switch (geolocationService) {
        'ip2location' => Ip2LocationClient(ip2LocationApiKey, c),
        'ipinfo' => IpInfoClient(c),
        _ => IpWhoisClient(c),
      };

  /// IP2Whois is preferred for domains; Virustotal is the fallback.
  WhoisClient? whoisClient(http.Client c) {
    if (ip2WhoisApiKey.isNotEmpty) return Ip2WhoisClient(ip2WhoisApiKey, c);
    if (vtApiKey.isNotEmpty) return VTClient(vtApiKey, c);
    return null;
  }

  ShodanClient? shodanClient(http.Client c) =>
      (useShodan || all) && shodanApiKey.isNotEmpty
          ? ShodanClient(shodanApiKey, c)
          : null;

  GreynoiseClient? greynoiseClient(http.Client c) =>
      (useGreynoise || all) && greynoiseApiKey.isNotEmpty
          ? GreynoiseClient(greynoiseApiKey, c)
          : null;

  AbuseIpDbClient? abuseIpDbClient(http.Client c) =>
      (useAbuseIpDb || all) && abuseIpDbApiKey.isNotEmpty
          ? AbuseIpDbClient(abuseIpDbApiKey, c)
          : null;

  UrlHausClient? urlHausClient(http.Client c) =>
      (useUrlHaus || all) && urlHausApiKey.isNotEmpty
          ? UrlHausClient(urlHausApiKey, c)
          : null;
}

/// Minimal dotenv parser (`KEY=value`, `#` comments, optional quotes).
Map<String, String> loadEnvFile(String? path) {
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
