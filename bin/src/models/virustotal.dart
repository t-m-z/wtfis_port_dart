import '../utils.dart';
import 'json.dart';

class LastAnalysisStats {
  final int harmless;
  final int malicious;
  final int suspicious;
  final int timeout;
  final int undetected;

  const LastAnalysisStats({
    required this.harmless,
    required this.malicious,
    required this.suspicious,
    required this.timeout,
    required this.undetected,
  });

  factory LastAnalysisStats.fromJson(Json j) {
    const m = 'LastAnalysisStats';
    return LastAnalysisStats(
      harmless: req<int>(j, 'harmless', m),
      malicious: req<int>(j, 'malicious', m),
      suspicious: req<int>(j, 'suspicious', m),
      timeout: req<int>(j, 'timeout', m),
      undetected: req<int>(j, 'undetected', m),
    );
  }

  Json toJson() => {
        'harmless': harmless,
        'malicious': malicious,
        'suspicious': suspicious,
        'timeout': timeout,
        'undetected': undetected,
      };
}

class AnalysisResult {
  final String category;
  final String engineName;
  final String method;
  final String result;

  const AnalysisResult(
      this.category, this.engineName, this.method, this.result);

  factory AnalysisResult.fromJson(Json j) {
    const m = 'AnalysisResult';
    return AnalysisResult(
      req<String>(j, 'category', m),
      req<String>(j, 'engine_name', m),
      req<String>(j, 'method', m),
      req<String>(j, 'result', m),
    );
  }
}

/// Port of `Domain` / `DomainAttributes`.
class VtDomain {
  final String id;
  final String type;
  final String? jarm;
  final Map<String, AnalysisResult> lastAnalysisResults;
  final LastAnalysisStats lastAnalysisStats;
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

  const VtDomain({
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

  factory VtDomain.fromJson(Json json) {
    const m = 'Domain';
    final data = reqMap(json, 'data', m);
    final a = reqMap(data, 'attributes', m);
    final results = reqMap(a, 'last_analysis_results', m).map((k, v) =>
        MapEntry(k, AnalysisResult.fromJson(Map<String, dynamic>.from(v))));
    final ranks = reqMap(a, 'popularity_ranks', m).map((k, v) =>
        MapEntry(k, req<int>(Map<String, dynamic>.from(v), 'rank', m)));
    return VtDomain(
      id: req<String>(data, 'id', m),
      type: req<String>(data, 'type', m),
      jarm: opt<String>(a, 'jarm', m),
      lastAnalysisResults: results,
      lastAnalysisStats:
          LastAnalysisStats.fromJson(reqMap(a, 'last_analysis_stats', m)),
      lastHttpsCertificateDate: opt<int>(a, 'last_https_certificate_date', m),
      lastModificationDate: opt<int>(a, 'last_modification_date', m),
      reputation: req<int>(a, 'reputation', m),
      tags: listOf<String>(a, 'tags', m, required: true),
      categories: transformCategories(reqMap(a, 'categories', m)),
      creationDate: opt<int>(a, 'creation_date', m),
      lastDnsRecordsDate: opt<int>(a, 'last_dns_records_date', m),
      lastUpdateDate: opt<int>(a, 'last_update_date', m),
      popularityRanks: ranks,
      registrar: opt<String>(a, 'registrar', m),
    );
  }

  /// Splits, lowercases, dedupes and sorts the VT categories.
  static List<String> transformCategories(Json v) {
    final cats = <String>{};
    for (final category in v.values.cast<String>()) {
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

  Json toJson() => {
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
        'creation_date': standardizeTimestamp(creationDate),
        'last_update_date': standardizeTimestamp(lastUpdateDate),
        'last_modification_date': standardizeTimestamp(lastModificationDate),
        'last_dns_records_date': standardizeTimestamp(lastDnsRecordsDate),
        'last_https_certificate_date':
            standardizeTimestamp(lastHttpsCertificateDate),
      };
}

class Resolution {
  final int date;
  final String hostName;
  final String resolver;
  final String ipAddress;
  final LastAnalysisStats ipAddressLastAnalysisStats;
  final LastAnalysisStats hostNameLastAnalysisStats;

  const Resolution({
    required this.date,
    required this.hostName,
    required this.resolver,
    required this.ipAddress,
    required this.ipAddressLastAnalysisStats,
    required this.hostNameLastAnalysisStats,
  });

  factory Resolution.fromJson(Json json) {
    const m = 'Resolution';
    final a = reqMap(json, 'attributes', m);
    return Resolution(
      date: req<int>(a, 'date', m),
      hostName: req<String>(a, 'host_name', m),
      resolver: req<String>(a, 'resolver', m),
      ipAddress: req<String>(a, 'ip_address', m),
      ipAddressLastAnalysisStats: LastAnalysisStats.fromJson(
          reqMap(a, 'ip_address_last_analysis_stats', m)),
      hostNameLastAnalysisStats: LastAnalysisStats.fromJson(
          reqMap(a, 'host_name_last_analysis_stats', m)),
    );
  }
}

/// Port of `Resolutions`.
class Resolutions {
  final int count;
  final List<Resolution> data;

  const Resolutions(this.count, this.data);

  factory Resolutions.fromJson(Json json) {
    const m = 'Resolutions';
    return Resolutions(
      req<int>(reqMap(json, 'meta', m), 'count', m),
      [
        for (final r in req<List>(json, 'data', m))
          Resolution.fromJson(Map<String, dynamic>.from(r)),
      ],
    );
  }

  /// IP list from the first [limit] resolutions.
  List<String> ipList(int limit) =>
      data.take(limit).map((r) => r.ipAddress).toList();
}
