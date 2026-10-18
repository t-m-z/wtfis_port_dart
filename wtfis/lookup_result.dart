part of 'lookup.dart';

/// Category of a [LookupError].
enum LookupErrorKind {
  /// Invalid input, e.g. an empty string or a private IP address.
  input,

  /// Invalid configuration, e.g. a missing API key.
  config,

  /// The API answered with a non-2xx HTTP status.
  http,

  /// The API could not be reached (DNS, connection, TLS, timeout).
  network,

  /// The API answered, but the data does not match the expected model.
  model,

  /// Any other unexpected error.
  internal,
}

/// A single error collected during a lookup.
class LookupError {
  /// Maximum number of characters of a response body kept in [body].
  static const maxBodyLength = 1000;

  final LookupErrorKind kind;

  /// Data source the error belongs to (e.g. `Virustotal`), or `input` /
  /// `config` for errors that are not tied to a source.
  final String source;

  final String message;

  /// HTTP status code ([LookupErrorKind.http] only).
  final int? statusCode;

  /// Requested URL without query parameters, so API keys passed as
  /// parameters never end up in the output.
  final Uri? url;

  /// Response body, truncated to [maxBodyLength] characters
  /// ([LookupErrorKind.http] only). May be an HTML error page.
  final String? body;

  LookupError(
    this.kind,
    this.source,
    this.message, {
    this.statusCode,
    Uri? url,
    String? body,
  })  : url = url == null ? null : _withoutQuery(url),
        body = body == null || body.length <= maxBodyLength
            ? body
            : '${body.substring(0, maxBodyLength)}…';

  /// Error for a non-2xx HTTP response.
  factory LookupError.http(String source, http.Response response, Uri url) {
    final status = response.statusCode;
    final reason = response.reasonPhrase;
    return LookupError(
      LookupErrorKind.http,
      source,
      '$status ${status >= 500 ? 'Server' : 'Client'} Error'
      '${reason == null || reason.isEmpty ? '' : ' ($reason)'}',
      statusCode: status,
      url: url,
      body: utf8.decode(response.bodyBytes, allowMalformed: true),
    );
  }

  static Uri _withoutQuery(Uri u) => Uri(
        scheme: u.scheme,
        host: u.host,
        port: u.hasPort ? u.port : null,
        path: u.path,
      );

  bool get isHttp => kind == LookupErrorKind.http;

  Map<String, dynamic> toJson() => {
        'source': source,
        'type': kind.name,
        'message': message,
        if (statusCode != null) 'status_code': statusCode,
        if (url != null) 'url': url.toString(),
        if (body != null) 'body': body,
      };

  @override
  String toString() =>
      '$source: $message${url == null ? '' : ' for url: $url'}';
}

/// Result of a domain or IP lookup: the collected data plus all errors that
/// occurred. Errors never abort the lookup; sources that failed are `null`
/// in [data] and listed in [errors].
class LookupResult {
  final String entity;

  /// `domain` or `ip`; `null` if the input could not be recognized.
  final String? type;

  /// Enrichment data, or `null` if the lookup could not be started
  /// (input/config errors). Domains: `virustotal`, `urlhaus`, `resolutions`,
  /// `whois`; IPs: `virustotal`, `geoasn`, `shodan`, `greynoise`,
  /// `abuseipdb`, `urlhaus`, `whois`.
  final Map<String, dynamic>? data;

  final List<LookupError> errors;

  LookupResult(this.entity,
      {this.type, this.data, List<LookupError>? errors})
      : errors = List<LookupError>.unmodifiable(
            errors ?? const <LookupError>[]);

  /// `true` if no error occurred.
  bool get ok => errors.isEmpty;

  /// Errors caused by HTTP responses.
  Iterable<LookupError> get httpErrors => errors.where((e) => e.isHttp);

  /// `true` if the lookup could not be started at all.
  bool get aborted => data == null;

  Map<String, dynamic> toJson() => {
        'entity': entity,
        'type': type,
        'ok': ok,
        ...?data,
        'errors': [for (final e in errors) e.toJson()],
      };

  String toJsonString({bool pretty = false}) =>
      (pretty ? const JsonEncoder.withIndent('  ') : const JsonEncoder())
          .convert(toJson());

  @override
  String toString() => toJsonString();
}
