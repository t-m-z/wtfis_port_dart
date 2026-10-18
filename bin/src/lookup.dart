// Dart port of wtfis - passive hostname, domain and IP lookup tool.
//
// The only name visible outside this file and its parts is [lookup].
// Everything else is private (`_`); privacy in Dart is per library, so the
// parts below share these names with each other.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

part 'clients.dart';
part 'config.dart';
part 'domain_handler.dart';
part 'exceptions.dart';
part 'handler.dart';
part 'ip_handler.dart';
part 'lookup_result.dart';
part 'models/ip_enrichment.dart';
part 'models/json.dart';
part 'models/virustotal.dart';
part 'models/whois.dart';
part 'utils.dart';

/// Looks up [input] at all configured sources. [input] is a domain / FQDN
/// or a public IPv4 / IPv6 address; defanged input like `example[.]com` or
/// `1[.]1[.]1[.]1` is accepted.
///
/// API keys and `WTFIS_DEFAULTS` are read from [environment] (default: the
/// process environment) and [envFile] (default: `~/.env.wtfis`); variables
/// in [environment] take precedence. The flags correspond to the command
/// line options and are toggled by `WTFIS_DEFAULTS` like in the original:
///
/// * [all], [useShodan], [useGreynoise], [useAbuseIpDb], [useUrlHaus]
/// * [maxResolutions] (0..10) - number of resolutions to enrich (domains
///   only; a non-default value for an IP address is a config error)
/// * [geolocationService] - `ip2location`, `ipinfo` or `ipwhois` (default)
/// * [httpClient] can be injected (e.g. for tests); otherwise a client is
///   created and closed internally.
///
/// Never throws. Every problem - invalid input, invalid configuration, HTTP
/// errors (status code, URL and response body), network errors and API data
/// that does not match the expected model - is collected in the result's
/// `errors`. Sources that failed are `null` in the result, all others are
/// filled as usual.
///
/// The result offers `entity`, `data`, `errors`, `ok`, `aborted`,
/// `httpErrors`, `toJson()` and `toJsonString(pretty: ...)`. Each error
/// offers `kind`, `source`, `message`, `statusCode`, `url`, `body` and
/// `toJson()`. The result type itself is private on purpose; it is used
/// through type inference.
// ignore: library_private_types_in_public_api
Future<_LookupResult> lookup(
  String input, {
  bool all = false,
  bool useShodan = false,
  bool useGreynoise = false,
  bool useAbuseIpDb = false,
  bool useUrlHaus = false,
  int maxResolutions = _defaultMaxResolutions,
  String? geolocationService,
  Map<String, String>? environment,
  String? envFile,
  http.Client? httpClient,
}) async {
  final ip = _parseIp(input);
  final type = ip == null ? 'domain' : 'ip';
  // Canonical notation, e.g. 2606:4700:4700:0:0:0:0:1111
  // -> 2606:4700:4700::1111
  final entity = ip == null
      ? _refang(input).trim()
      : InternetAddress.fromRawAddress(ip.rawAddress).address;

  _LookupResult inputError(String message, {String? type}) =>
      _LookupResult(entity, type: type, errors: [
        _LookupError(
            _LookupErrorKind.input, 'input', '$message (got "$input")'),
      ]);

  if (entity.isEmpty) {
    return inputError('Expected a domain, FQDN or IP address');
  }
  if (ip != null && !_isGlobal(ip)) {
    return inputError(
        'Not a public IP address (private, loopback, link-local, multicast, '
        'documentation or reserved range)',
        type: type);
  }

  final _WtfisConfig cfg;
  try {
    cfg = _WtfisConfig.fromEnvironment(
      environment: environment,
      envFile: envFile,
      all: all,
      useShodan: useShodan,
      useGreynoise: useGreynoise,
      useAbuseIpDb: useAbuseIpDb,
      useUrlHaus: useUrlHaus,
      maxResolutions: maxResolutions,
      geolocationService: geolocationService,
    );
  } on Object catch (e) {
    // e.g. unreadable ~/.env.wtfis
    return _LookupResult(entity, type: type, errors: [
      _LookupError(_LookupErrorKind.config, 'config', e.toString()),
    ]);
  }
  final configErrors = [
    ...cfg.validate(),
    if (ip != null && maxResolutions != _defaultMaxResolutions)
      _LookupError(_LookupErrorKind.config, 'config',
          'maxResolutions is not applicable to IP addresses'),
  ];
  if (configErrors.isNotEmpty) {
    return _LookupResult(entity, type: type, errors: configErrors);
  }

  final errors = <_LookupError>[];
  final client = httpClient ?? http.Client();
  final _BaseHandler handler = ip == null
      ? _DomainHandler(entity, cfg, client, errors)
      : _IpAddressHandler(entity, cfg, client, errors);
  try {
    await handler.fetchData();
  } on Object catch (e) {
    // Safety net: the clients collect their errors themselves, so this only
    // catches programming errors. The data fetched so far is kept.
    errors.add(
        _LookupError(_LookupErrorKind.internal, 'wtfis', e.toString()));
  } finally {
    if (httpClient == null) client.close();
  }
  return _LookupResult(entity,
      type: handler.type, data: handler.toJson(), errors: errors);
}
