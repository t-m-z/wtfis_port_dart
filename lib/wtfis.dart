/// Dart port of wtfis - passive hostname, domain and IP lookup tool.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

import 'src/config.dart';
import 'src/domain_handler.dart';
import 'src/utils.dart';

export 'src/clients.dart';
export 'src/config.dart' show WtfisConfig, loadEnvFile;
export 'src/domain_handler.dart';
export 'src/exceptions.dart';
export 'src/utils.dart' show isIp, refang, standardizeTimestamp;

/// Looks up [domain] (domain or FQDN, defanged input like `example[.]com` is
/// accepted) at all configured sources and returns the result as a JSON
/// string.
///
/// * [config] defaults to [WtfisConfig.fromEnvironment], i.e. API keys are
///   read from the environment and `~/.env.wtfis`.
/// * [httpClient] can be injected (e.g. for tests); otherwise a client is
///   created and closed internally.
/// * [pretty] enables indented output.
///
/// Sources that cannot be reached fail open and are listed under
/// `"warnings"`. Throws a [HandlerException] if an API returns data that does
/// not match the expected model, and an [ArgumentError] for IP input.
Future<String> lookupDomain(
  String domain, {
  WtfisConfig? config,
  http.Client? httpClient,
  bool pretty = false,
}) async {
  if (isIp(domain) || refang(domain).trim().isEmpty) {
    throw ArgumentError.value(domain, 'domain', 'Expected a domain or FQDN');
  }

  final client = httpClient ?? http.Client();
  try {
    final handler =
        DomainHandler(domain, config ?? WtfisConfig.fromEnvironment(), client);
    await handler.fetchData();
    final encoder =
        pretty ? const JsonEncoder.withIndent('  ') : const JsonEncoder();
    return encoder.convert(handler.toJson());
  } finally {
    if (httpClient == null) client.close();
  }
}
