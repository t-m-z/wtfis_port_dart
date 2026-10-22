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

  /// Readable text form of [toJson]: one `key: value` per line, nested
  /// values indented by [indent], no braces or brackets.
  ///
  /// * Top-level sections (`virustotal`, `resolutions`, ...) and the items
  ///   of lists of objects (resolutions, URLhaus URLs, errors) are
  ///   separated by blank lines; list items start with `- `.
  /// * Lists of simple values are written comma-separated in one line;
  ///   empty values and missing sections are written as `-`.
  /// * Fields without a value (`null` or empty text) below the top level
  ///   are left out; with [includeNulls] they are written as `-`.
  /// * Multi-line values (e.g. an HTML error page) are indented below
  ///   their key.
  String toText({String indent = '  ', bool includeNulls = false}) {
    final w = _TextWriter(indent, includeNulls);
    for (final e in toJson().entries) {
      final section = _TextWriter.isBlock(e.value);
      if (section) w.blankLine();
      w.entry(e.key, e.value, 0);
      if (section) w.blankLine();
    }
    return w.toString();
  }

  @override
  String toString() => toJsonString();
}

/// Writes JSON-like data as indented `key: value` lines (see
/// [LookupResult.toText]).
class _TextWriter {
  final String indent;
  final bool includeNulls;
  final List<String> _lines = [];

  _TextWriter(this.indent, this.includeNulls);

  /// Values that get their own block of lines.
  static bool isBlock(Object? v) =>
      (v is Map<dynamic, dynamic> && v.isNotEmpty) ||
      (v is List<dynamic> && v.any((x) => x is Map<dynamic, dynamic>));

  /// Adds a blank line unless there is one already (or nothing yet).
  void blankLine() {
    if (_lines.isNotEmpty && _lines.last.isNotEmpty) _lines.add('');
  }

  void entries(Map<dynamic, dynamic> map, int level) {
    for (final e in map.entries) {
      if (_isMissing(e.value) && !includeNulls) continue;
      entry('${e.key}', e.value, level);
    }
  }

  void entry(String key, Object? value, int level) {
    final pad = indent * level;
    if (value is Map<dynamic, dynamic> && value.isNotEmpty) {
      _lines.add('$pad$key:');
      entries(value, level + 1);
    } else if (isBlock(value)) {
      _lines.add('$pad$key:');
      _items(value as List<dynamic>, level + 1);
    } else if (value is List<dynamic>) {
      final text = value.isEmpty ? '-' : value.map(_scalar).join(', ');
      _lines.add('$pad$key: $text');
    } else if (value is Map<dynamic, dynamic>) {
      _lines.add('$pad$key: -');
    } else {
      final text = _scalar(value);
      if (text.contains('\n')) {
        _lines.add('$pad$key:');
        for (final line in text.split(RegExp(r'\r?\n'))) {
          _lines.add('$pad$indent$line');
        }
      } else {
        _lines.add('$pad$key: $text');
      }
    }
  }

  /// Items of a list of objects: `- ` before the first line of each item
  /// (padded to the width of [indent] if it consists of spaces), [indent]
  /// before the following lines, a blank line between items.
  void _items(List<dynamic> items, int level) {
    final pad = indent * level;
    final marker = indent.length >= 2 && indent.trim().isEmpty &&
            !indent.contains('\t')
        ? '-'.padRight(indent.length)
        : '- ';
    for (var i = 0; i < items.length; i++) {
      if (i > 0) _lines.add('');
      final Object? item = items[i];
      final sub = _TextWriter(indent, includeNulls);
      if (item is Map<dynamic, dynamic>) {
        sub.entries(item, 0);
      } else {
        sub._lines.add(_scalar(item));
      }
      for (var j = 0; j < sub._lines.length; j++) {
        final line = sub._lines[j];
        _lines.add(line.isEmpty ? '' : '$pad${j == 0 ? marker : indent}$line');
      }
    }
  }

  static bool _isMissing(Object? v) => v == null || v == '';

  static String _scalar(Object? v) => _isMissing(v) ? '-' : '$v';

  @override
  String toString() {
    while (_lines.isNotEmpty && _lines.last.isEmpty) {
      _lines.removeLast();
    }
    return _lines.join('\n');
  }
}
