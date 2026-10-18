import '../exceptions.dart';
import '../utils.dart';
import 'json.dart';

/// Normalized IP geolocation and ASN data (port of `IpGeoAsnBase` and the
/// `ipwhois`, `ipinfo` and `ip2location` models).
class IpGeoAsn {
  final String source;
  final String ip;
  final String? city;
  final String? country;
  final String? region;
  final String? asn;
  final String? org;
  final String? isp;
  final String? domain;
  final String? hostname;
  final String? isProxy;
  final String? isAnycast;
  final String? link;

  const IpGeoAsn({
    required this.source,
    required this.ip,
    this.city,
    this.country,
    this.region,
    this.asn,
    this.org,
    this.isp,
    this.domain,
    this.hostname,
    this.isProxy,
    this.isAnycast,
    this.link,
  });

  /// https://ipwhois.io/documentation
  factory IpGeoAsn.fromIpWhois(Json j) {
    const m = 'IpWhois';
    final c = optMap(j, 'connection', m) ?? const {};
    return IpGeoAsn(
      source: 'IPWhois',
      ip: laxStr(req<Object>(j, 'ip', m))!,
      city: laxStr(j['city']),
      country: laxStr(j['country']),
      region: laxStr(j['region']),
      asn: laxStr(c['asn']),
      org: laxStr(c['org']),
      isp: laxStr(c['isp']),
      domain: laxStr(c['domain']),
      hostname: laxStr(j['hostname']),
      isProxy: laxStr(j['is_proxy']),
      isAnycast: laxStr(j['is_anycast']),
      link: laxStr(j['link']),
    );
  }

  /// https://ipinfo.io/developers
  factory IpGeoAsn.fromIpInfo(Json j) {
    const m = 'IpInfo';
    final ip = laxStr(req<Object>(j, 'ip', m))!;
    String? asn;
    var org = laxStr(j['org']);
    // Extract ASN and Org from the org field
    final match = RegExp(r'AS(\d+)\s+(.+)$').firstMatch(org ?? '');
    if (match != null) {
      asn = match.group(1);
      org = match.group(2)!.trim();
    }
    return IpGeoAsn(
      source: 'IPinfo',
      ip: ip,
      city: laxStr(j['city']),
      country: laxStr(j['country']),
      region: laxStr(j['region']),
      asn: asn,
      org: org,
      isp: laxStr(j['isp']),
      domain: laxStr(j['domain']),
      hostname: laxStr(j['hostname']),
      isProxy: laxStr(j['is_proxy']),
      isAnycast: laxStr(j['anycast']),
      link: 'https://ipinfo.io/$ip',
    );
  }

  /// https://www.ip2location.io/ip2location-documentation
  factory IpGeoAsn.fromIp2Location(Json j) {
    const m = 'Ip2Location';
    return IpGeoAsn(
      source: 'IP2Location',
      ip: laxStr(req<Object>(j, 'ip', m))!,
      city: laxStr(j['city_name']),
      region: laxStr(j['region_name']),
      country: laxStr(j['country_name']),
      asn: laxStr(j['asn']),
      org: laxStr(j['as']),
      isp: laxStr(j['isp']),
      domain: laxStr(j['domain']),
      hostname: laxStr(j['hostname']),
      isProxy: laxStr(j['is_proxy']),
      isAnycast: laxStr(j['is_anycast']),
      link: laxStr(j['link']),
    );
  }

  Json toJson() => {
        'source': source,
        'ip': ip,
        'city': city,
        'region': region,
        'country': country,
        'asn': asn,
        'org': org,
        'isp': isp,
        'domain': domain,
        'hostname': hostname,
        'is_proxy': isProxy,
        'is_anycast': isAnycast,
        'link': link,
      };
}

class PortData {
  final int port;
  final String? product;
  final String transport;

  const PortData(this.port, this.product, this.transport);
}

/// Port of `ShodanIp`.
class ShodanIp {
  final Json _raw;
  final String ipStr;
  final List<PortData> data;

  ShodanIp._(this._raw, this.ipStr, this.data);

  factory ShodanIp.fromJson(Json j) {
    const m = 'ShodanIp';
    for (final f in const ['country_code', 'country_name', 'last_update']) {
      req<String>(j, f, m);
    }
    final data = [
      for (final p in req<List>(j, 'data', m))
        PortData(
          req<int>(Map<String, dynamic>.from(p), 'port', m),
          (p as Map)['product'] as String?,
          req<String>(Map<String, dynamic>.from(p), 'transport', m),
        ),
    ];
    return ShodanIp._(j, req<String>(j, 'ip_str', m), data);
  }

  /// Groups open ports by product; ports without product end up in "Other".
  Map<String, List<String>> groupPortsByProduct() {
    final result = <String, List<String>>{};
    final unknown = <String>[];
    for (final p in data) {
      final entry = '${p.port}/${p.transport}';
      if (p.product != null && p.product!.isNotEmpty) {
        result.putIfAbsent(p.product!, () => []).add(entry);
      } else {
        unknown.add(entry);
      }
    }
    if (unknown.isNotEmpty) result['Other'] = unknown;
    return result;
  }

  Json toJson() => {
        'ip': ipStr,
        'asn': laxStr(_raw['asn']),
        'org': _raw['org'],
        'isp': _raw['isp'],
        'os': _raw['os'],
        'city': _raw['city'],
        'region_name': _raw['region_name'],
        'country_code': _raw['country_code'],
        'country_name': _raw['country_name'],
        'ports': _raw['ports'],
        'services': groupPortsByProduct(),
        'tags': _raw['tags'],
        'last_update': standardizeTimestamp(_raw['last_update']),
        'link': 'https://www.shodan.io/host/$ipStr',
      };
}

/// Port of `GreynoiseIp`.
class GreynoiseIp {
  final String ip;
  final bool noise;
  final bool riot;
  final String message;
  final String link;
  final String? classification;
  final String? name;
  final String? lastSeen;

  const GreynoiseIp({
    required this.ip,
    required this.noise,
    required this.riot,
    required this.message,
    required this.link,
    this.classification,
    this.name,
    this.lastSeen,
  });

  factory GreynoiseIp.fromJson(Json j) {
    const m = 'GreynoiseIp';
    return GreynoiseIp(
      ip: req<String>(j, 'ip', m),
      noise: req<bool>(j, 'noise', m),
      riot: req<bool>(j, 'riot', m),
      message: req<String>(j, 'message', m),
      link: req<String>(j, 'link', m),
      classification: opt<String>(j, 'classification', m),
      name: opt<String>(j, 'name', m),
      lastSeen: opt<String>(j, 'last_seen', m),
    );
  }

  Json toJson() => {
        'ip': ip,
        'noise': noise,
        'riot': riot,
        'classification': classification,
        'name': name,
        'last_seen': lastSeen,
        'message': message,
        'link': link,
      };
}

/// Port of `AbuseIpDb`.
class AbuseIpDb {
  final String ipAddress;
  final int abuseConfidenceScore;
  final String isp;
  final Json _raw;

  AbuseIpDb._(this._raw, this.ipAddress, this.abuseConfidenceScore, this.isp);

  factory AbuseIpDb.fromJson(Json j) {
    const m = 'AbuseIpDb';
    return AbuseIpDb._(
      j,
      req<String>(j, 'ipAddress', m),
      req<int>(j, 'abuseConfidenceScore', m),
      req<String>(j, 'isp', m),
    );
  }

  Json toJson() => {
        'ip_address': ipAddress,
        'abuse_confidence_score': abuseConfidenceScore,
        'is_public': _raw['isPublic'],
        'ip_version': _raw['ipVersion'],
        'is_whitelisted': _raw['isWhitelisted'],
        'country_code': _raw['countryCode'],
        'usage_type': _raw['usageType'],
        'isp': isp,
        'domain': _raw['domain'],
        'hostnames': _raw['hostnames'],
        'is_tor': _raw['isTor'],
        'total_reports': _raw['totalReports'],
        'num_distinct_users': _raw['numDistinctUsers'],
        'last_reported_at': standardizeTimestamp(_raw['lastReportedAt']),
        'link': 'https://www.abuseipdb.com/check/$ipAddress',
      };
}

int? _laxInt(Object? v, String field) {
  if (v == null || v == '') return null;
  if (v is int) return v;
  if (v is String && int.tryParse(v) != null) return int.parse(v);
  throw ModelException('UrlHaus: field "$field" is not an integer');
}

class UrlHausUrl {
  final String id;
  final String urlhausReference;
  final String url;
  final String urlStatus;
  final String dateAdded;
  final String threat;
  final String reporter;
  final bool larted;
  final int? takedownTimeSeconds;
  final List<String> tags;

  const UrlHausUrl({
    required this.id,
    required this.urlhausReference,
    required this.url,
    required this.urlStatus,
    required this.dateAdded,
    required this.threat,
    required this.reporter,
    required this.larted,
    this.takedownTimeSeconds,
    this.tags = const [],
  });

  factory UrlHausUrl.fromJson(Json j) {
    const m = 'UrlHausUrl';
    final larted = laxStr(req<Object>(j, 'larted', m))!.toLowerCase();
    if (larted != 'true' && larted != 'false') {
      throw const ModelException('UrlHausUrl: invalid "larted" value');
    }
    return UrlHausUrl(
      id: laxStr(req<Object>(j, 'id', m))!,
      urlhausReference: req<String>(j, 'urlhaus_reference', m),
      url: req<String>(j, 'url', m),
      urlStatus: req<String>(j, 'url_status', m),
      dateAdded: req<String>(j, 'date_added', m),
      threat: req<String>(j, 'threat', m),
      reporter: req<String>(j, 'reporter', m),
      larted: larted == 'true',
      takedownTimeSeconds:
          _laxInt(j['takedown_time_seconds'], 'takedown_time_seconds'),
      tags: listOf<String>(j, 'tags', m),
    );
  }

  Json toJson() => {
        'id': id,
        'url': url,
        'url_status': urlStatus,
        'date_added': dateAdded,
        'threat': threat,
        'reporter': reporter,
        'larted': larted,
        'takedown_time_seconds': takedownTimeSeconds,
        'tags': tags,
        'urlhaus_reference': urlhausReference,
      };
}

/// Port of `UrlHaus`.
class UrlHaus {
  final String queryStatus;
  final String? urlhausReference;
  final String? host;
  final String? firstseen;
  final int? urlCount;
  final Map<String, String>? blacklists;
  final List<UrlHausUrl> urls;

  const UrlHaus({
    required this.queryStatus,
    this.urlhausReference,
    this.host,
    this.firstseen,
    this.urlCount,
    this.blacklists,
    this.urls = const [],
  });

  factory UrlHaus.fromJson(Json j) {
    const m = 'UrlHaus';
    final bl = optMap(j, 'blacklists', m);
    return UrlHaus(
      queryStatus: req<String>(j, 'query_status', m),
      urlhausReference: opt<String>(j, 'urlhaus_reference', m),
      host: opt<String>(j, 'host', m),
      firstseen: opt<String>(j, 'firstseen', m),
      urlCount: _laxInt(j['url_count'], 'url_count'),
      blacklists: bl == null
          ? null
          : {
              'spamhaus_dbl': req<String>(bl, 'spamhaus_dbl', m),
              'surbl': req<String>(bl, 'surbl', m),
            },
      urls: [
        for (final u in opt<List>(j, 'urls', m) ?? const [])
          UrlHausUrl.fromJson(Map<String, dynamic>.from(u)),
      ],
    );
  }

  int get onlineUrlCount => urls.where((u) => u.urlStatus == 'online').length;

  List<String> get tags => ({for (final u in urls) ...u.tags}.toList()..sort());

  Json toJson() => {
        'host': host,
        'query_status': queryStatus,
        'firstseen': firstseen,
        'url_count': urlCount,
        'online_url_count': onlineUrlCount,
        'blacklists': blacklists,
        'tags': tags,
        'urls': [for (final u in urls) u.toJson()],
        'urlhaus_reference': urlhausReference,
      };
}
