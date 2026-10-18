part of '../lookup.dart';

/// Normalized IP geolocation and ASN data (port of `IpGeoAsnBase` and the
/// `ipwhois`, `ipinfo` and `ip2location` models).
class _IpGeoAsn {
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

  const _IpGeoAsn({
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
  factory _IpGeoAsn.fromIpWhois(_Json j) {
    const m = 'IpWhois';
    final c = _optMap(j, 'connection', m) ?? const <String, dynamic>{};
    return _IpGeoAsn(
      source: 'IPWhois',
      ip: _laxStr(_req<Object>(j, 'ip', m))!,
      city: _laxStr(j['city']),
      country: _laxStr(j['country']),
      region: _laxStr(j['region']),
      asn: _laxStr(c['asn']),
      org: _laxStr(c['org']),
      isp: _laxStr(c['isp']),
      domain: _laxStr(c['domain']),
      hostname: _laxStr(j['hostname']),
      isProxy: _laxStr(j['is_proxy']),
      isAnycast: _laxStr(j['is_anycast']),
      link: _laxStr(j['link']),
    );
  }

  /// https://ipinfo.io/developers
  factory _IpGeoAsn.fromIpInfo(_Json j) {
    const m = 'IpInfo';
    final ip = _laxStr(_req<Object>(j, 'ip', m))!;
    String? asn;
    var org = _laxStr(j['org']);
    // Extract ASN and Org from the org field
    final match = RegExp(r'AS(\d+)\s+(.+)$').firstMatch(org ?? '');
    if (match != null) {
      asn = match.group(1);
      org = match.group(2)!.trim();
    }
    return _IpGeoAsn(
      source: 'IPinfo',
      ip: ip,
      city: _laxStr(j['city']),
      country: _laxStr(j['country']),
      region: _laxStr(j['region']),
      asn: asn,
      org: org,
      isp: _laxStr(j['isp']),
      domain: _laxStr(j['domain']),
      hostname: _laxStr(j['hostname']),
      isProxy: _laxStr(j['is_proxy']),
      isAnycast: _laxStr(j['anycast']),
      link: 'https://ipinfo.io/$ip',
    );
  }

  /// https://www.ip2location.io/ip2location-documentation
  factory _IpGeoAsn.fromIp2Location(_Json j) {
    const m = 'Ip2Location';
    return _IpGeoAsn(
      source: 'IP2Location',
      ip: _laxStr(_req<Object>(j, 'ip', m))!,
      city: _laxStr(j['city_name']),
      region: _laxStr(j['region_name']),
      country: _laxStr(j['country_name']),
      asn: _laxStr(j['asn']),
      org: _laxStr(j['as']),
      isp: _laxStr(j['isp']),
      domain: _laxStr(j['domain']),
      hostname: _laxStr(j['hostname']),
      isProxy: _laxStr(j['is_proxy']),
      isAnycast: _laxStr(j['is_anycast']),
      link: _laxStr(j['link']),
    );
  }

  _Json toJson() => {
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

class _PortData {
  final int port;
  final String? product;
  final String transport;

  const _PortData(this.port, this.product, this.transport);
}

/// Port of `ShodanIp`.
class _ShodanIp {
  final _Json _raw;
  final String ipStr;
  final List<_PortData> data;

  _ShodanIp._(this._raw, this.ipStr, this.data);

  factory _ShodanIp.fromJson(_Json j) {
    const m = 'ShodanIp';
    for (final f in const ['country_code', 'country_name', 'last_update']) {
      _req<String>(j, f, m);
    }
    final data = [
      for (final p in _mapList(j, 'data', m, required: true))
        _PortData(
          _req<int>(p, 'port', m),
          _opt<String>(p, 'product', m),
          _req<String>(p, 'transport', m),
        ),
    ];
    return _ShodanIp._(j, _req<String>(j, 'ip_str', m), data);
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

  _Json toJson() => {
        'ip': ipStr,
        'asn': _laxStr(_raw['asn']),
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
        'last_update': _standardizeTimestamp(_raw['last_update']),
        'link': 'https://www.shodan.io/host/$ipStr',
      };
}

/// Port of `GreynoiseIp`.
class _GreynoiseIp {
  final String ip;
  final bool noise;
  final bool riot;
  final String message;
  final String link;
  final String? classification;
  final String? name;
  final String? lastSeen;

  const _GreynoiseIp({
    required this.ip,
    required this.noise,
    required this.riot,
    required this.message,
    required this.link,
    this.classification,
    this.name,
    this.lastSeen,
  });

  factory _GreynoiseIp.fromJson(_Json j) {
    const m = 'GreynoiseIp';
    return _GreynoiseIp(
      ip: _req<String>(j, 'ip', m),
      noise: _req<bool>(j, 'noise', m),
      riot: _req<bool>(j, 'riot', m),
      message: _req<String>(j, 'message', m),
      link: _req<String>(j, 'link', m),
      classification: _opt<String>(j, 'classification', m),
      name: _opt<String>(j, 'name', m),
      lastSeen: _opt<String>(j, 'last_seen', m),
    );
  }

  _Json toJson() => {
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
class _AbuseIpDb {
  final String ipAddress;
  final int abuseConfidenceScore;
  final String isp;
  final _Json _raw;

  _AbuseIpDb._(this._raw, this.ipAddress, this.abuseConfidenceScore, this.isp);

  factory _AbuseIpDb.fromJson(_Json j) {
    const m = 'AbuseIpDb';
    return _AbuseIpDb._(
      j,
      _req<String>(j, 'ipAddress', m),
      _req<int>(j, 'abuseConfidenceScore', m),
      _req<String>(j, 'isp', m),
    );
  }

  _Json toJson() => {
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
        'last_reported_at': _standardizeTimestamp(_raw['lastReportedAt']),
        'link': 'https://www.abuseipdb.com/check/$ipAddress',
      };
}

int? _laxInt(Object? v, String field) {
  if (v == null || v == '') return null;
  if (v is int) return v;
  if (v is String && int.tryParse(v) != null) return int.parse(v);
  throw _ModelException('UrlHaus: field "$field" is not an integer');
}

class _UrlHausUrl {
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

  const _UrlHausUrl({
    required this.id,
    required this.urlhausReference,
    required this.url,
    required this.urlStatus,
    required this.dateAdded,
    required this.threat,
    required this.reporter,
    required this.larted,
    this.takedownTimeSeconds,
    this.tags = const <String>[],
  });

  factory _UrlHausUrl.fromJson(_Json j) {
    const m = 'UrlHausUrl';
    final larted = _laxStr(_req<Object>(j, 'larted', m))!.toLowerCase();
    if (larted != 'true' && larted != 'false') {
      throw const _ModelException('UrlHausUrl: invalid "larted" value');
    }
    return _UrlHausUrl(
      id: _laxStr(_req<Object>(j, 'id', m))!,
      urlhausReference: _req<String>(j, 'urlhaus_reference', m),
      url: _req<String>(j, 'url', m),
      urlStatus: _req<String>(j, 'url_status', m),
      dateAdded: _req<String>(j, 'date_added', m),
      threat: _req<String>(j, 'threat', m),
      reporter: _req<String>(j, 'reporter', m),
      larted: larted == 'true',
      takedownTimeSeconds:
          _laxInt(j['takedown_time_seconds'], 'takedown_time_seconds'),
      tags: _listOf<String>(j, 'tags', m),
    );
  }

  _Json toJson() => {
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
class _UrlHaus {
  final String queryStatus;
  final String? urlhausReference;
  final String? host;
  final String? firstseen;
  final int? urlCount;
  final Map<String, String>? blacklists;
  final List<_UrlHausUrl> urls;

  const _UrlHaus({
    required this.queryStatus,
    this.urlhausReference,
    this.host,
    this.firstseen,
    this.urlCount,
    this.blacklists,
    this.urls = const <_UrlHausUrl>[],
  });

  factory _UrlHaus.fromJson(_Json j) {
    const m = 'UrlHaus';
    final bl = _optMap(j, 'blacklists', m);
    return _UrlHaus(
      queryStatus: _req<String>(j, 'query_status', m),
      urlhausReference: _opt<String>(j, 'urlhaus_reference', m),
      host: _opt<String>(j, 'host', m),
      firstseen: _opt<String>(j, 'firstseen', m),
      urlCount: _laxInt(j['url_count'], 'url_count'),
      blacklists: bl == null
          ? null
          : {
              'spamhaus_dbl': _req<String>(bl, 'spamhaus_dbl', m),
              'surbl': _req<String>(bl, 'surbl', m),
            },
      urls: [
        for (final u in _mapList(j, 'urls', m)) _UrlHausUrl.fromJson(u),
      ],
    );
  }

  int get onlineUrlCount => urls.where((u) => u.urlStatus == 'online').length;

  List<String> get tags => ({for (final u in urls) ...u.tags}.toList()..sort());

  _Json toJson() => {
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
