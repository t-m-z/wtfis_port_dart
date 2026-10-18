import 'dart:convert';

import 'package:http/http.dart' as http;

import 'exceptions.dart';
import 'models/ip_enrichment.dart';
import 'models/json.dart';
import 'models/virustotal.dart';
import 'models/whois.dart';
import 'utils.dart';

/// Base client using `package:http` (port of `BaseRequestsClient`).
abstract class BaseClient {
  final http.Client http_;
  BaseClient(this.http_);

  String get name;
  String get baseUrl;
  Map<String, String> get defaultHeaders => const {};

  Future<dynamic> get(String path,
      {Map<String, String>? params, Map<String, String>? headers}) async {
    final uri = Uri.parse(baseUrl + path)
        .replace(queryParameters: params?.isEmpty ?? true ? null : params);
    final resp =
        await http_.get(uri, headers: {...defaultHeaders, ...?headers});
    return _decode(resp, uri);
  }

  Future<dynamic> post(String path,
      {Map<String, String>? data, Map<String, String>? headers}) async {
    final uri = Uri.parse(baseUrl + path);
    final resp = await http_
        .post(uri, body: data, headers: {...defaultHeaders, ...?headers});
    return _decode(resp, uri);
  }

  dynamic _decode(http.Response resp, Uri uri) {
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw HttpStatusException(resp.statusCode, uri, resp.body);
    }
    try {
      return jsonDecode(utf8.decode(resp.bodyBytes));
    } on FormatException catch (e) {
      throw ModelException('Invalid JSON from $name: ${e.message}');
    }
  }
}

/// Client used for whois lookups.
abstract interface class WhoisClient {
  String get name;
  Future<Whois> getWhois(String entity);
}

/// Client used for IP enrichments.
abstract interface class IpEnricherClient<T> {
  String get name;
  Future<Map<String, T>> enrichIps(List<String> ips);
}

Json _map(Object? v) => Map<String, dynamic>.from(v as Map);

class VTClient extends BaseClient implements WhoisClient {
  final String apiKey;
  VTClient(this.apiKey, super.http_);

  @override
  String get name => 'Virustotal';
  @override
  String get baseUrl => 'https://www.virustotal.com/api/v3';
  @override
  Map<String, String> get defaultHeaders =>
      {'x-apikey': apiKey, 'Accept': 'application/json'};

  Future<VtDomain> getDomain(String domain) async =>
      VtDomain.fromJson(_map(await get('/domains/$domain')));

  Future<Resolutions> getDomainResolutions(String domain) async =>
      Resolutions.fromJson(_map(await get('/domains/$domain/resolutions')));

  @override
  Future<Whois> getWhois(String entity) async {
    final kind = isIp(entity) ? 'ip_addresses' : 'domains';
    return Whois.fromVirustotal(
        _map(await get('/$kind/$entity/historical_whois')));
  }
}

class Ip2WhoisClient extends BaseClient implements WhoisClient {
  final String apiKey;
  Ip2WhoisClient(this.apiKey, super.http_);

  @override
  String get name => 'IP2Whois';
  @override
  String get baseUrl => 'https://api.ip2whois.com/v2';

  @override
  Future<Whois> getWhois(String entity) async {
    try {
      return Whois.fromIp2Whois(_map(
          await get('/', params: {'key': apiKey, 'domain': refang(entity)})));
    } on HttpStatusException catch (e) {
      // Let a 404 or invalid domain pass
      if (e.statusCode == 404 ||
          (e.statusCode == 400 && _errorCode(e.body) == 10007)) {
        return Whois.fromIp2Whois(const {});
      }
      rethrow;
    }
  }

  static int? _errorCode(String body) {
    try {
      return (jsonDecode(body) as Map)['error']?['error_code'] as int?;
    } catch (_) {
      return null;
    }
  }
}

class IpWhoisClient extends BaseClient implements IpEnricherClient<IpGeoAsn> {
  IpWhoisClient(super.http_);

  @override
  String get name => 'IPWhois';
  @override
  String get baseUrl => 'https://ipwho.is';

  @override
  Future<Map<String, IpGeoAsn>> enrichIps(List<String> ips) async {
    final result = <String, IpGeoAsn>{};
    for (final ip in ips) {
      final data = _map(await get('/$ip'));
      if (data['success'] == true) {
        final m = IpGeoAsn.fromIpWhois(data);
        result[m.ip] = m;
      }
    }
    return result;
  }
}

class IpInfoClient extends BaseClient implements IpEnricherClient<IpGeoAsn> {
  IpInfoClient(super.http_);

  @override
  String get name => 'IPinfo';
  @override
  String get baseUrl => 'https://ipinfo.io';

  @override
  Future<Map<String, IpGeoAsn>> enrichIps(List<String> ips) async {
    final result = <String, IpGeoAsn>{};
    for (final ip in ips) {
      final data = _map(await get('/$ip/json'));
      if (data.isNotEmpty) {
        final m = IpGeoAsn.fromIpInfo(data);
        result[m.ip] = m;
      }
    }
    return result;
  }
}

class Ip2LocationClient extends BaseClient
    implements IpEnricherClient<IpGeoAsn> {
  final String apiKey;
  Ip2LocationClient(this.apiKey, super.http_);

  @override
  String get name => 'IP2Location';
  @override
  String get baseUrl => 'https://api.ip2location.io';

  @override
  Future<Map<String, IpGeoAsn>> enrichIps(List<String> ips) async {
    final result = <String, IpGeoAsn>{};
    for (final ip in ips) {
      final m = IpGeoAsn.fromIp2Location(_map(
          await get('/', params: {'key': apiKey, 'ip': ip, 'format': 'json'})));
      result[m.ip] = m;
    }
    return result;
  }
}

class ShodanClient extends BaseClient implements IpEnricherClient<ShodanIp> {
  final String apiKey;
  ShodanClient(this.apiKey, super.http_);

  @override
  String get name => 'Shodan';
  @override
  String get baseUrl => 'https://api.shodan.io/shodan';

  @override
  Future<Map<String, ShodanIp>> enrichIps(List<String> ips) async {
    final result = <String, ShodanIp>{};
    for (final ip in ips) {
      try {
        final m = ShodanIp.fromJson(
            _map(await get('/host/$ip', params: {'key': apiKey})));
        result[m.ipStr] = m;
      } on HttpStatusException catch (e) {
        // 404 means the IP is invalid or not in Shodan
        if (e.statusCode != 404) rethrow;
      }
    }
    return result;
  }
}

class GreynoiseClient extends BaseClient
    implements IpEnricherClient<GreynoiseIp> {
  final String apiKey;
  GreynoiseClient(this.apiKey, super.http_);

  @override
  String get name => 'Greynoise';
  @override
  String get baseUrl => 'https://api.greynoise.io/v3/community';

  @override
  Future<Map<String, GreynoiseIp>> enrichIps(List<String> ips) async {
    final result = <String, GreynoiseIp>{};
    for (final ip in ips) {
      try {
        final m = GreynoiseIp.fromJson(
            _map(await get('/$ip', headers: {'key': apiKey})));
        result[m.ip] = m;
      } on HttpStatusException catch (e) {
        if (e.statusCode != 404) rethrow;
      }
    }
    return result;
  }
}

class AbuseIpDbClient extends BaseClient
    implements IpEnricherClient<AbuseIpDb> {
  final String apiKey;
  AbuseIpDbClient(this.apiKey, super.http_);

  @override
  String get name => 'AbuseIPDB';
  @override
  String get baseUrl => 'https://api.abuseipdb.com/api/v2';

  @override
  Future<Map<String, AbuseIpDb>> enrichIps(List<String> ips) async {
    final result = <String, AbuseIpDb>{};
    for (final ip in ips) {
      final resp = _map(await get('/check',
          params: {'ipAddress': ip, 'maxAgeInDays': '90'},
          headers: {'key': apiKey, 'Accept': 'application/json'}));
      final m = AbuseIpDb.fromJson(reqMap(resp, 'data', 'AbuseIpDb'));
      result[m.ipAddress] = m;
    }
    return result;
  }
}

class UrlHausClient extends BaseClient implements IpEnricherClient<UrlHaus> {
  final String apiKey;
  UrlHausClient(this.apiKey, super.http_);

  @override
  String get name => 'URLhaus';
  @override
  String get baseUrl => 'https://urlhaus-api.abuse.ch/v1';

  /// Same lookup for domains and IPs.
  Future<Map<String, UrlHaus>> enrich(List<String> entities) async {
    final result = <String, UrlHaus>{};
    for (final entity in entities) {
      final m = UrlHaus.fromJson(_map(await post('/host',
          data: {'host': entity}, headers: {'Auth-Key': apiKey})));
      if (m.host != null) result[m.host!] = m;
    }
    return result;
  }

  Future<Map<String, UrlHaus>> enrichDomains(List<String> domains) =>
      enrich(domains);

  @override
  Future<Map<String, UrlHaus>> enrichIps(List<String> ips) => enrich(ips);
}
