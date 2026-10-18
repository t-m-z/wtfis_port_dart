part of 'lookup.dart';

/// Base client using `package:http` (port of `BaseRequestsClient`).
///
/// No method throws: HTTP, network and data errors are appended to [errors]
/// and the affected call returns `null` (or skips the affected item).
abstract class _BaseClient {
  final http.Client http_;

  /// Shared error list of the running lookup.
  final List<LookupError> errors;

  _BaseClient(this.http_, this.errors);

  String get name;
  String get baseUrl;
  Map<String, String> get defaultHeaders => const <String, String>{};

  /// GET request returning the decoded JSON object, or `null` on error.
  ///
  /// Non-2xx responses for which [tolerate] returns `true` are not errors;
  /// they yield an empty map ("no data").
  Future<_Json?> get(String path,
      {Map<String, String>? params,
      Map<String, String>? headers,
      bool Function(http.Response)? tolerate}) {
    final uri = Uri.parse(baseUrl + path)
        .replace(queryParameters: params?.isEmpty ?? true ? null : params);
    return _request(
        uri, () => http_.get(uri, headers: {...defaultHeaders, ...?headers}),
        tolerate: tolerate);
  }

  /// POST request (form data) returning the decoded JSON object, or `null`
  /// on error.
  Future<_Json?> post(String path,
      {Map<String, String>? data, Map<String, String>? headers}) {
    final uri = Uri.parse(baseUrl + path);
    return _request(
        uri,
        () => http_
            .post(uri, body: data, headers: {...defaultHeaders, ...?headers}));
  }

  Future<_Json?> _request(Uri uri, Future<http.Response> Function() send,
      {bool Function(http.Response)? tolerate}) async {
    final http.Response resp;
    try {
      resp = await send();
    } on http.ClientException catch (e) {
      return _networkError(uri, e.message);
    } on IOException catch (e) {
      return _networkError(uri, e.toString());
    } on TimeoutException catch (e) {
      return _networkError(uri, e.toString());
    }

    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      if (tolerate != null && tolerate(resp)) return <String, dynamic>{};
      errors.add(LookupError.http(name, resp, uri));
      return null;
    }

    final Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(resp.bodyBytes));
    } on FormatException catch (e) {
      return _modelError('Invalid JSON: ${e.message}', uri);
    }
    if (decoded is! Map<dynamic, dynamic>) {
      return _modelError('Expected a JSON object', uri);
    }
    try {
      return _asJson(decoded, 'response');
    } on _ModelException catch (e) {
      return _modelError(e.message, uri);
    }
  }

  Null _networkError(Uri uri, String message) {
    errors.add(LookupError(LookupErrorKind.network, name, message, url: uri));
    return null;
  }

  Null _modelError(String message, [Uri? uri]) {
    errors.add(LookupError(LookupErrorKind.model, name,
        'Data model validation error: $message',
        url: uri));
    return null;
  }

  /// Builds a model from [json]; validation errors are recorded and yield
  /// `null`. A `null` [json] (request failed, already recorded) yields
  /// `null` as well.
  T? parse<T>(_Json? json, T Function(_Json json) build) {
    if (json == null) return null;
    try {
      return build(json);
    } on _ModelException catch (e) {
      return _modelError(e.message);
    } on TypeError catch (e) {
      return _modelError(e.toString());
    } on FormatException catch (e) {
      return _modelError(e.message);
    }
  }
}

/// Client used for whois lookups.
abstract interface class _WhoisClient {
  String get name;
  Future<_Whois?> getWhois(String entity);
}

/// Client used for IP enrichments.
abstract interface class _IpEnricherClient<T> {
  String get name;
  Future<Map<String, T>> enrichIps(List<String> ips);
}

class _VTClient extends _BaseClient implements _WhoisClient {
  final String apiKey;
  _VTClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'Virustotal';
  @override
  String get baseUrl => 'https://www.virustotal.com/api/v3';
  @override
  Map<String, String> get defaultHeaders =>
      {'x-apikey': apiKey, 'Accept': 'application/json'};

  Future<_VtDomain?> getDomain(String domain) async =>
      parse(await get('/domains/$domain'), _VtDomain.fromJson);

  Future<_VtIpAddress?> getIpAddress(String ip) async =>
      parse(await get('/ip_addresses/$ip'), _VtIpAddress.fromJson);

  Future<_Resolutions?> getDomainResolutions(String domain) async => parse(
      await get('/domains/$domain/resolutions'), _Resolutions.fromJson);

  @override
  Future<_Whois?> getWhois(String entity) async {
    final kind = _isIp(entity) ? 'ip_addresses' : 'domains';
    return parse(await get('/$kind/$entity/historical_whois'),
        _Whois.fromVirustotal);
  }
}

class _Ip2WhoisClient extends _BaseClient implements _WhoisClient {
  final String apiKey;
  _Ip2WhoisClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'IP2Whois';
  @override
  String get baseUrl => 'https://api.ip2whois.com/v2';

  @override
  Future<_Whois?> getWhois(String entity) async => parse(
      await get('/',
          params: {'key': apiKey, 'domain': _refang(entity)},
          // Let a 404 or invalid domain pass (empty whois)
          tolerate: (r) =>
              r.statusCode == 404 ||
              (r.statusCode == 400 && _errorCode(r) == 10007)),
      _Whois.fromIp2Whois);

  static int? _errorCode(http.Response resp) {
    try {
      final Object? body = jsonDecode(utf8.decode(resp.bodyBytes));
      if (body case {'error': {'error_code': final int code}}) return code;
    } on FormatException {
      // not JSON
    }
    return null;
  }
}

class _IpWhoisClient extends _BaseClient
    implements _IpEnricherClient<_IpGeoAsn> {
  _IpWhoisClient(super.http_, super.errors);

  @override
  String get name => 'IPWhois';
  @override
  String get baseUrl => 'https://ipwho.is';

  @override
  Future<Map<String, _IpGeoAsn>> enrichIps(List<String> ips) async {
    final result = <String, _IpGeoAsn>{};
    for (final ip in ips) {
      final data = await get('/$ip');
      if (data?['success'] != true) continue;
      if (parse(data, _IpGeoAsn.fromIpWhois) case final m?) result[m.ip] = m;
    }
    return result;
  }
}

class _IpInfoClient extends _BaseClient
    implements _IpEnricherClient<_IpGeoAsn> {
  _IpInfoClient(super.http_, super.errors);

  @override
  String get name => 'IPinfo';
  @override
  String get baseUrl => 'https://ipinfo.io';

  @override
  Future<Map<String, _IpGeoAsn>> enrichIps(List<String> ips) async {
    final result = <String, _IpGeoAsn>{};
    for (final ip in ips) {
      final data = await get('/$ip/json');
      if (data == null || data.isEmpty) continue;
      if (parse(data, _IpGeoAsn.fromIpInfo) case final m?) result[m.ip] = m;
    }
    return result;
  }
}

class _Ip2LocationClient extends _BaseClient
    implements _IpEnricherClient<_IpGeoAsn> {
  final String apiKey;
  _Ip2LocationClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'IP2Location';
  @override
  String get baseUrl => 'https://api.ip2location.io';

  @override
  Future<Map<String, _IpGeoAsn>> enrichIps(List<String> ips) async {
    final result = <String, _IpGeoAsn>{};
    for (final ip in ips) {
      final data =
          await get('/', params: {'key': apiKey, 'ip': ip, 'format': 'json'});
      if (parse(data, _IpGeoAsn.fromIp2Location) case final m?) {
        result[m.ip] = m;
      }
    }
    return result;
  }
}

class _ShodanClient extends _BaseClient
    implements _IpEnricherClient<_ShodanIp> {
  final String apiKey;
  _ShodanClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'Shodan';
  @override
  String get baseUrl => 'https://api.shodan.io/shodan';

  @override
  Future<Map<String, _ShodanIp>> enrichIps(List<String> ips) async {
    final result = <String, _ShodanIp>{};
    for (final ip in ips) {
      // 404 means the IP is invalid or not in Shodan
      final data = await get('/host/$ip',
          params: {'key': apiKey}, tolerate: (r) => r.statusCode == 404);
      if (data == null || data.isEmpty) continue;
      if (parse(data, _ShodanIp.fromJson) case final m?) result[m.ipStr] = m;
    }
    return result;
  }
}

class _GreynoiseClient extends _BaseClient
    implements _IpEnricherClient<_GreynoiseIp> {
  final String apiKey;
  _GreynoiseClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'Greynoise';
  @override
  String get baseUrl => 'https://api.greynoise.io/v3/community';

  @override
  Future<Map<String, _GreynoiseIp>> enrichIps(List<String> ips) async {
    final result = <String, _GreynoiseIp>{};
    for (final ip in ips) {
      final data = await get('/$ip',
          headers: {'key': apiKey}, tolerate: (r) => r.statusCode == 404);
      if (data == null || data.isEmpty) continue;
      if (parse(data, _GreynoiseIp.fromJson) case final m?) result[m.ip] = m;
    }
    return result;
  }
}

class _AbuseIpDbClient extends _BaseClient
    implements _IpEnricherClient<_AbuseIpDb> {
  final String apiKey;
  _AbuseIpDbClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'AbuseIPDB';
  @override
  String get baseUrl => 'https://api.abuseipdb.com/api/v2';

  @override
  Future<Map<String, _AbuseIpDb>> enrichIps(List<String> ips) async {
    final result = <String, _AbuseIpDb>{};
    for (final ip in ips) {
      final resp = await get('/check',
          params: {'ipAddress': ip, 'maxAgeInDays': '90'},
          headers: {'key': apiKey, 'Accept': 'application/json'});
      final m = parse(
          resp, (j) => _AbuseIpDb.fromJson(_reqMap(j, 'data', 'AbuseIpDb')));
      if (m != null) result[m.ipAddress] = m;
    }
    return result;
  }
}

class _UrlHausClient extends _BaseClient
    implements _IpEnricherClient<_UrlHaus> {
  final String apiKey;
  _UrlHausClient(this.apiKey, super.http_, super.errors);

  @override
  String get name => 'URLhaus';
  @override
  String get baseUrl => 'https://urlhaus-api.abuse.ch/v1';

  /// Same lookup for domains and IPs.
  Future<Map<String, _UrlHaus>> enrich(List<String> entities) async {
    final result = <String, _UrlHaus>{};
    for (final entity in entities) {
      final data = await post('/host',
          data: {'host': entity}, headers: {'Auth-Key': apiKey});
      final m = parse(data, _UrlHaus.fromJson);
      if (m?.host case final host?) result[host] = m!;
    }
    return result;
  }

  Future<Map<String, _UrlHaus>> enrichDomains(List<String> domains) =>
      enrich(domains);

  @override
  Future<Map<String, _UrlHaus>> enrichIps(List<String> ips) => enrich(ips);
}
