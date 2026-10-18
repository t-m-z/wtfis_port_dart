part of '../lookup.dart';

class _LastAnalysisStats {
  final int harmless;
  final int malicious;
  final int suspicious;
  final int timeout;
  final int undetected;

  const _LastAnalysisStats({
    required this.harmless,
    required this.malicious,
    required this.suspicious,
    required this.timeout,
    required this.undetected,
  });

  factory _LastAnalysisStats.fromJson(_Json j) {
    const m = 'LastAnalysisStats';
    return _LastAnalysisStats(
      harmless: _req<int>(j, 'harmless', m),
      malicious: _req<int>(j, 'malicious', m),
      suspicious: _req<int>(j, 'suspicious', m),
      timeout: _req<int>(j, 'timeout', m),
      undetected: _req<int>(j, 'undetected', m),
    );
  }

  _Json toJson() => {
        'harmless': harmless,
        'malicious': malicious,
        'suspicious': suspicious,
        'timeout': timeout,
        'undetected': undetected,
      };
}

class _AnalysisResult {
  final String category;
  final String engineName;
  final String method;
  final String result;

  const _AnalysisResult(
      this.category, this.engineName, this.method, this.result);

  factory _AnalysisResult.fromJson(_Json j) {
    const m = 'AnalysisResult';
    return _AnalysisResult(
      _req<String>(j, 'category', m),
      _req<String>(j, 'engine_name', m),
      _req<String>(j, 'method', m),
      _req<String>(j, 'result', m),
    );
  }
}

/// Port of `Domain` / `DomainAttributes`.
class _VtDomain {
  final String id;
  final String type;
  final String? jarm;
  final Map<String, _AnalysisResult> lastAnalysisResults;
  final _LastAnalysisStats lastAnalysisStats;
  final int? lastHttpsCertificateDate;
  final int? lastModificationDate;
  final int reputation;
  final List<String> tags;
  final List<String> categories;
  final int? creationDate;
  final int? lastDnsRecordsDate;
  final int? lastUpdateDate;
  final Map<String, int> popularityRanks;
  final String? registrar;

  const _VtDomain({
    required this.id,
    required this.type,
    this.jarm,
    required this.lastAnalysisResults,
    required this.lastAnalysisStats,
    this.lastHttpsCertificateDate,
    this.lastModificationDate,
    required this.reputation,
    required this.tags,
    required this.categories,
    this.creationDate,
    this.lastDnsRecordsDate,
    this.lastUpdateDate,
    required this.popularityRanks,
    this.registrar,
  });

  factory _VtDomain.fromJson(_Json json) {
    const m = 'Domain';
    final data = _reqMap(json, 'data', m);
    final a = _reqMap(data, 'attributes', m);
    final results = _mapOfMaps(a, 'last_analysis_results', m)
        .map((k, v) => MapEntry(k, _AnalysisResult.fromJson(v)));
    final ranks = _mapOfMaps(a, 'popularity_ranks', m)
        .map((k, v) => MapEntry(k, _req<int>(v, 'rank', m)));
    return _VtDomain(
      id: _req<String>(data, 'id', m),
      type: _req<String>(data, 'type', m),
      jarm: _opt<String>(a, 'jarm', m),
      lastAnalysisResults: results,
      lastAnalysisStats:
          _LastAnalysisStats.fromJson(_reqMap(a, 'last_analysis_stats', m)),
      lastHttpsCertificateDate: _opt<int>(a, 'last_https_certificate_date', m),
      lastModificationDate: _opt<int>(a, 'last_modification_date', m),
      reputation: _req<int>(a, 'reputation', m),
      tags: _listOf<String>(a, 'tags', m, required: true),
      categories: transformCategories(_reqMap(a, 'categories', m)),
      creationDate: _opt<int>(a, 'creation_date', m),
      lastDnsRecordsDate: _opt<int>(a, 'last_dns_records_date', m),
      lastUpdateDate: _opt<int>(a, 'last_update_date', m),
      popularityRanks: ranks,
      registrar: _opt<String>(a, 'registrar', m),
    );
  }

  /// Splits, lowercases, dedupes and sorts the VT categories.
  static List<String> transformCategories(_Json v) {
    final cats = <String>{};
    for (final Object? category in v.values) {
      if (category is! String) {
        throw const _ModelException('Domain: categories must be strings');
      }
      final delimiter =
          const [', ', ',', '/', ' / '].where(category.contains).firstOrNull;
      if (delimiter != null) {
        cats.addAll(category.toLowerCase().split(delimiter));
      } else {
        cats.add(category.toLowerCase());
      }
    }
    return cats.toList()..sort();
  }

  /// Vendors whose verdict was "malicious".
  List<String> get maliciousVendors => [
        for (final e in lastAnalysisResults.entries)
          if (e.value.category == 'malicious') e.key,
      ];

  _Json toJson() => {
        'id': id,
        'type': type,
        'link': 'https://www.virustotal.com/gui/domain/$id',
        'last_analysis_stats': lastAnalysisStats.toJson(),
        'malicious_vendors': maliciousVendors,
        'reputation': reputation,
        'popularity_ranks': popularityRanks,
        'categories': categories,
        'tags': tags,
        'registrar': registrar,
        'jarm': jarm,
        'creation_date': _standardizeTimestamp(creationDate),
        'last_update_date': _standardizeTimestamp(lastUpdateDate),
        'last_modification_date': _standardizeTimestamp(lastModificationDate),
        'last_dns_records_date': _standardizeTimestamp(lastDnsRecordsDate),
        'last_https_certificate_date':
            _standardizeTimestamp(lastHttpsCertificateDate),
      };
}

/// Port of `IpAddress` / `IpAttributes`.
class _VtIpAddress {
  final String id;
  final String type;
  final String? jarm;
  final Map<String, _AnalysisResult> lastAnalysisResults;
  final _LastAnalysisStats lastAnalysisStats;
  final int? lastHttpsCertificateDate;
  final int? lastModificationDate;
  final int reputation;
  final List<String> tags;
  final String? asn;
  final String? asOwner;
  final String? continent;
  final String? country;
  final String? network;

  const _VtIpAddress({
    required this.id,
    required this.type,
    this.jarm,
    required this.lastAnalysisResults,
    required this.lastAnalysisStats,
    this.lastHttpsCertificateDate,
    this.lastModificationDate,
    required this.reputation,
    required this.tags,
    this.asn,
    this.asOwner,
    this.continent,
    this.country,
    this.network,
  });

  factory _VtIpAddress.fromJson(_Json json) {
    const m = 'IpAddress';
    final data = _reqMap(json, 'data', m);
    final a = _reqMap(data, 'attributes', m);
    final results = _mapOfMaps(a, 'last_analysis_results', m)
        .map((k, v) => MapEntry(k, _AnalysisResult.fromJson(v)));
    return _VtIpAddress(
      id: _req<String>(data, 'id', m),
      type: _req<String>(data, 'type', m),
      jarm: _opt<String>(a, 'jarm', m),
      lastAnalysisResults: results,
      lastAnalysisStats:
          _LastAnalysisStats.fromJson(_reqMap(a, 'last_analysis_stats', m)),
      lastHttpsCertificateDate: _opt<int>(a, 'last_https_certificate_date', m),
      lastModificationDate: _opt<int>(a, 'last_modification_date', m),
      reputation: _req<int>(a, 'reputation', m),
      tags: _listOf<String>(a, 'tags', m, required: true),
      asn: _laxStr(a['asn']),
      asOwner: _opt<String>(a, 'as_owner', m),
      continent: _opt<String>(a, 'continent', m),
      country: _opt<String>(a, 'country', m),
      network: _opt<String>(a, 'network', m),
    );
  }

  /// Vendors whose verdict was "malicious".
  List<String> get maliciousVendors => [
        for (final e in lastAnalysisResults.entries)
          if (e.value.category == 'malicious') e.key,
      ];

  _Json toJson() => {
        'id': id,
        'type': type,
        'link': 'https://www.virustotal.com/gui/ip-address/$id',
        'last_analysis_stats': lastAnalysisStats.toJson(),
        'malicious_vendors': maliciousVendors,
        'reputation': reputation,
        'tags': tags,
        'asn': asn,
        'as_owner': asOwner,
        'network': network,
        'continent': continent,
        'country': country,
        'jarm': jarm,
        'last_modification_date': _standardizeTimestamp(lastModificationDate),
        'last_https_certificate_date':
            _standardizeTimestamp(lastHttpsCertificateDate),
      };
}

class _Resolution {
  final int date;
  final String hostName;
  final String resolver;
  final String ipAddress;
  final _LastAnalysisStats ipAddressLastAnalysisStats;
  final _LastAnalysisStats hostNameLastAnalysisStats;

  const _Resolution({
    required this.date,
    required this.hostName,
    required this.resolver,
    required this.ipAddress,
    required this.ipAddressLastAnalysisStats,
    required this.hostNameLastAnalysisStats,
  });

  factory _Resolution.fromJson(_Json json) {
    const m = 'Resolution';
    final a = _reqMap(json, 'attributes', m);
    return _Resolution(
      date: _req<int>(a, 'date', m),
      hostName: _req<String>(a, 'host_name', m),
      resolver: _req<String>(a, 'resolver', m),
      ipAddress: _req<String>(a, 'ip_address', m),
      ipAddressLastAnalysisStats: _LastAnalysisStats.fromJson(
          _reqMap(a, 'ip_address_last_analysis_stats', m)),
      hostNameLastAnalysisStats: _LastAnalysisStats.fromJson(
          _reqMap(a, 'host_name_last_analysis_stats', m)),
    );
  }
}

/// Port of `Resolutions`.
class _Resolutions {
  final int count;
  final List<_Resolution> data;

  const _Resolutions(this.count, this.data);

  factory _Resolutions.fromJson(_Json json) {
    const m = 'Resolutions';
    return _Resolutions(
      _req<int>(_reqMap(json, 'meta', m), 'count', m),
      [
        for (final r in _mapList(json, 'data', m, required: true))
          _Resolution.fromJson(r),
      ],
    );
  }

  /// IP list from the first [limit] resolutions.
  List<String> ipList(int limit) =>
      data.take(limit).map((r) => r.ipAddress).toList();
}
