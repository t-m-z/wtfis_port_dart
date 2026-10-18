import 'package:http/http.dart' as http;

import 'config.dart';
import 'domain_handler.dart';
import 'lookup_result.dart';
import 'utils.dart';

/// Looks up [domain] (domain or FQDN, defanged input like `example[.]com` is
/// accepted) at all configured sources.
///
/// * [config] defaults to [WtfisConfig.fromEnvironment], i.e. API keys are
///   read from the environment and `~/.env.wtfis`.
/// * [httpClient] can be injected (e.g. for tests); otherwise a client is
///   created and closed internally.
///
/// Never throws. Every problem - invalid input, invalid configuration, HTTP
/// errors (status code, URL and response body), network errors and API data
/// that does not match the expected model - is collected in
/// [LookupResult.errors]. Sources that failed are `null` in the result, all
/// others are filled as usual.
Future<LookupResult> lookup(
  String domain, {
  WtfisConfig? config,
  http.Client? httpClient,
}) async {
  final entity = refang(domain).trim();

  if (entity.isEmpty || isIp(entity)) {
    return LookupResult(entity, errors: [
      LookupError(LookupErrorKind.input, 'input',
          'Expected a domain or FQDN (got "$domain")'),
    ]);
  }

  final WtfisConfig cfg;
  try {
    cfg = config ?? WtfisConfig.fromEnvironment();
  } on Object catch (e) {
    // e.g. unreadable ~/.env.wtfis
    return LookupResult(entity, errors: [
      LookupError(LookupErrorKind.config, 'config', e.toString()),
    ]);
  }
  final configErrors = cfg.validate();
  if (configErrors.isNotEmpty) {
    return LookupResult(entity, errors: configErrors);
  }

  final errors = <LookupError>[];
  final client = httpClient ?? http.Client();
  final handler = DomainHandler(entity, cfg, client, errors);
  try {
    await handler.fetchData();
  } on Object catch (e) {
    // Safety net: the clients collect their errors themselves, so this only
    // catches programming errors. The data fetched so far is kept.
    errors.add(LookupError(LookupErrorKind.internal, 'wtfis', e.toString()));
  } finally {
    if (httpClient == null) client.close();
  }
  return LookupResult(entity, data: handler.toJson(), errors: errors);
}

/// Like [lookup], but returns the result directly as JSON string
/// (indented if [pretty] is set). Never throws; errors are listed under
/// `"errors"`.
Future<String> lookupDomain(
  String domain, {
  WtfisConfig? config,
  http.Client? httpClient,
  bool pretty = false,
}) async =>
    (await lookup(domain, config: config, httpClient: httpClient))
        .toJsonString(pretty: pretty);
