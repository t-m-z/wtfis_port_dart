// Dart port of wtfis - passive hostname, domain and IP lookup tool.
//
// Visible outside this file and its parts are only [lookup] and its result
// types [LookupResult], [LookupError] and [LookupErrorKind]. Everything
// else is private (`_`); privacy in Dart is per library, so the parts below
// share these names with each other.

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

/// Looks up [address] - a domain / FQDN or a public IPv4 / IPv6 address -
/// with all enrichments. Defanged input like `example[.]com` or
/// `1[.]1[.]1[.]1` is accepted.
///
/// Every source whose API key is given is queried; sources without a key
/// are skipped. The geolocation service ([geolocationService]: `ipwhois`
/// (default) or `ipinfo`, both without key, or `ip2location` with
/// [ip2LocationApiKey]) is always queried.
///
/// * Domains: VirusTotal (domain, resolutions), geolocation, Shodan,
///   Greynoise and AbuseIPDB for the first [maxResolutions] (0..10) resolved
///   IPs, URLhaus, Whois (IP2Whois, fallback VirusTotal).
/// * IPs: VirusTotal (IP), geolocation, Shodan, URLhaus, Greynoise,
///   AbuseIPDB, Whois (VirusTotal). [maxResolutions] does not apply.
/// * [httpClient] can be injected (e.g. for tests); otherwise a client is
///   created and closed internally.
///
/// Never throws. Every problem - invalid input, invalid configuration, HTTP
/// errors (status code, URL and response body), network errors and API data
/// that does not match the expected model - is collected in
/// [LookupResult.errors]. Sources that failed are `null` in the result, all
/// others are filled as usual.
Future<LookupResult> lookup(
  String address, {
  String? vtApiKey,
  String? ip2WhoisApiKey,
  String? ip2LocationApiKey,
  String? shodanApiKey,
  String? greynoiseApiKey,
  String? abuseIpDbApiKey,
  String? urlHausApiKey,
  String geolocationService = _defaultGeolocationService,
  int maxResolutions = _defaultMaxResolutions,
  http.Client? httpClient,
}) async {
  final ip = _parseIp(address);
  final type = ip == null ? 'domain' : 'ip';
  // Canonical notation, e.g. 2606:4700:4700:0:0:0:0:1111
  // -> 2606:4700:4700::1111
  final entity = ip == null
      ? _refang(address).trim()
      : InternetAddress.fromRawAddress(ip.rawAddress).address;

  LookupResult inputError(String message, {String? type}) =>
      LookupResult(entity, type: type, errors: [
        LookupError(
            LookupErrorKind.input, 'input', '$message (got "$address")'),
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

  final cfg = _WtfisConfig(
    vtApiKey: vtApiKey,
    ip2WhoisApiKey: ip2WhoisApiKey,
    ip2LocationApiKey: ip2LocationApiKey,
    shodanApiKey: shodanApiKey,
    greynoiseApiKey: greynoiseApiKey,
    abuseIpDbApiKey: abuseIpDbApiKey,
    urlHausApiKey: urlHausApiKey,
    geolocationService: geolocationService,
    maxResolutions: maxResolutions,
  );
  final configErrors = [
    ...cfg.validate(),
    if (ip != null && maxResolutions != _defaultMaxResolutions)
      LookupError(LookupErrorKind.config, 'config',
          'maxResolutions is not applicable to IP addresses'),
  ];
  if (configErrors.isNotEmpty) {
    return LookupResult(entity, type: type, errors: configErrors);
  }

  final errors = <LookupError>[];
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
        LookupError(LookupErrorKind.internal, 'wtfis', e.toString()));
  } finally {
    if (httpClient == null) client.close();
  }
  return LookupResult(entity,
      type: handler.type, data: handler.toJson(), errors: errors);
}
