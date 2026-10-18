import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import '../bin/src/config.dart';
import '../bin/src/exceptions.dart';
import '../bin/src/lookup.dart';
import '../bin/src/lookup_result.dart';
import '../bin/src/models/ip_enrichment.dart';
import '../bin/src/models/virustotal.dart';
import '../bin/src/models/whois.dart';
import '../bin/src/utils.dart';

dynamic testData(String name) =>
    jsonDecode(File('test/test_data/$name').readAsStringSync());

http.Response jsonResponse(Object? body, [int status = 200]) =>
    http.Response(jsonEncode(body), status,
        headers: {'content-type': 'application/json'});

/// Mock of all APIs serving the "gist.github.com" fixtures.
MockClient gistApis(
    {int vtStatus = 200,
    String? vtErrorBody,
    Object? vtDomainBody,
    int? shodanStatus,
    List<Uri>? requests}) {
  final ipwhois = testData('ipwhois_gist.json') as Map;
  final shodan = testData('shodan_gist.json') as Map;
  return MockClient((req) async {
    requests?.add(req.url);
    final url = req.url;
    switch (url.host) {
      case 'www.virustotal.com':
        if (vtStatus != 200) {
          return vtErrorBody == null
              ? jsonResponse({}, vtStatus)
              : http.Response(vtErrorBody, vtStatus,
                  headers: {'content-type': 'text/html'});
        }
        if (url.path.endsWith('/resolutions')) {
          return jsonResponse(testData('vt_resolutions_gist.json'));
        }
        if (url.path.endsWith('/historical_whois')) {
          return jsonResponse(testData('vt_whois_gist.json'));
        }
        return jsonResponse(vtDomainBody ?? testData('vt_domain_gist.json'));
      case 'ipwho.is':
        return jsonResponse(ipwhois[url.pathSegments.last]);
      case 'api.ip2whois.com':
        return jsonResponse(testData('ip2whois_whois_gist.json'));
      case 'api.shodan.io':
        if (shodanStatus != null) return http.Response('', shodanStatus);
        final ip = url.pathSegments.last;
        return shodan.containsKey(ip)
            ? jsonResponse(shodan[ip])
            : jsonResponse({'error': 'No information available'}, 404);
      case 'urlhaus-api.abuse.ch':
        expect(req.method, 'POST');
        expect(req.headers['Auth-Key'], 'eve');
        return jsonResponse(
            (testData('urlhaus_gist.json') as Map)['gist.github.com']);
    }
    return http.Response('not found', 404);
  });
}

void main() {
  group('lookupDomain', () {
    test('returns enriched JSON (VT + IPWhois + VT whois)', () async {
      final json = await lookupDomain('gist[.]github[.]com',
          config: WtfisConfig(vtApiKey: 'foo'), httpClient: gistApis());
      final out = jsonDecode(json) as Map<String, dynamic>;

      expect(out['entity'], 'gist.github.com');
      expect(out['type'], 'domain');
      expect(out['ok'], isTrue);
      expect(out['errors'], isEmpty);

      final vt = out['virustotal'];
      expect(vt['id'], 'gist.github.com');
      expect(vt['last_analysis_stats'], {
        'harmless': 84,
        'malicious': 0,
        'suspicious': 0,
        'timeout': 0,
        'undetected': 10,
      });
      expect(vt['malicious_vendors'], isEmpty);
      expect(vt['categories'], [
        'advice',
        'file sharing/storage',
        'information technology',
        'media sharing',
        'social networks',
      ]);
      expect(
          vt['popularity_ranks'], {'Majestic': 532, 'Cisco Umbrella': 39463});
      expect(vt['creation_date'], '2007-10-09T18:20:50Z');

      final res = out['resolutions'];
      expect(res['total'], 37);
      expect((res['data'] as List).map((r) => r['ip']),
          ['13.234.210.38', '192.30.255.113', '13.234.176.102']);
      final first = res['data'][0];
      expect(first['resolved'], '2022-08-06T14:56:20Z');
      expect(first['geoasn']['source'], 'IPWhois');
      expect(first['geoasn']['asn'], '16509');
      expect(first['geoasn']['city'], 'Mumbai');
      expect(first['shodan'], isNull);

      final whois = out['whois'];
      expect(whois['source'], 'virustotal');
      expect(whois['domain'], 'github.com');
      expect(whois['registrar'], 'MarkMonitor Inc.');
      expect(whois['name_servers'], hasLength(8));
      expect(whois['name_servers'][0], 'dns1.p08.nsone.net');
      expect(whois['date_changed'], '2020-09-08T09:18:27Z');
      expect(whois['date_created'], '2007-10-09T18:20:50Z');
      expect(whois['date_expires'], '2022-10-09T18:20:50Z');
    });

    test('uses IP2Whois when its key is set, plus Shodan and URLhaus',
        () async {
      final out = jsonDecode(await lookupDomain('gist.github.com',
          config: WtfisConfig(
            vtApiKey: 'foo',
            ip2WhoisApiKey: 'alice',
            shodanApiKey: 'hunter2',
            urlHausApiKey: 'eve',
            all: true,
          ),
          httpClient: gistApis()));

      expect(out['whois']['source'], 'ip2whois');
      expect(out['whois']['registrar'], 'MarkMonitor, Inc.');
      expect(out['whois']['organization'], 'GitHub, Inc.');
      expect(out['whois']['state'], 'CA');
      expect(out['whois']['date_created'], '2007-10-09T18:20:50Z');

      final shodan = out['resolutions']['data'][0]['shodan'];
      expect(shodan['ip'], '13.234.210.38');
      expect(shodan['services'], {
        'Other': ['22/tcp', '80/tcp', '443/tcp']
      });

      expect(out['urlhaus']['host'], 'gist.github.com');
      expect(out['urlhaus']['online_url_count'], 1);
      expect(out['urlhaus']['url_count'], 3248);
      expect(out['urlhaus']['urls'][0]['larted'], isTrue);
    });

    test('without any API key only geolocation-free output is returned',
        () async {
      final requests = <Uri>[];
      final out = jsonDecode(await lookupDomain('example.com',
          config: WtfisConfig(), httpClient: gistApis(requests: requests)));
      expect(requests, isEmpty);
      expect(out['virustotal'], isNull);
      expect(out['resolutions'], isNull);
      expect(out['whois'], isNull);
    });

    test('maxResolutions = 0 skips resolutions and IP enrichment', () async {
      final requests = <Uri>[];
      final out = jsonDecode(await lookupDomain('gist.github.com',
          config: WtfisConfig(vtApiKey: 'foo', maxResolutions: 0),
          httpClient: gistApis(requests: requests)));
      expect(out['resolutions'], isNull);
      expect(requests.where((u) => u.host == 'ipwho.is'), isEmpty);
      expect(out['virustotal'], isNotNull);
      expect(out['whois'], isNotNull);
    });

    test('HTTP errors are collected with status, url and body', () async {
      final out = jsonDecode(await lookupDomain('gist.github.com',
          config: WtfisConfig(vtApiKey: 'foo'),
          httpClient: gistApis(vtStatus: 401)));
      expect(out['ok'], isFalse);
      expect(out['virustotal'], isNull);
      final errors = out['errors'] as List;
      // domain, resolutions and whois (VT fallback) all fail
      expect(errors, hasLength(3));
      expect(errors[0], {
        'source': 'Virustotal',
        'type': 'http',
        'message': startsWith('401 Client Error'),
        'status_code': 401,
        'url': 'https://www.virustotal.com/api/v3/domains/gist.github.com',
        'body': '{}',
      });
      expect(jsonEncode(out), isNot(contains('foo')));
    });

    test('HTML error pages are kept (truncated) in the error', () async {
      final page = '<html><body><h1>502 Bad Gateway</h1>'
          '${'x' * 2000}</body></html>';
      final result = await lookup('gist.github.com',
          config: WtfisConfig(vtApiKey: 'foo'),
          httpClient: gistApis(vtStatus: 502, vtErrorBody: page));
      final e = result.httpErrors.first;
      expect(e.statusCode, 502);
      expect(e.message, startsWith('502 Server Error'));
      expect(e.body, startsWith('<html><body><h1>502 Bad Gateway</h1>'));
      expect(e.body!.length, LookupError.maxBodyLength + 1);
    });

    test('API keys in query parameters are not part of error urls', () async {
      final result = await lookup('gist.github.com',
          config: WtfisConfig(
              vtApiKey: 'foo', shodanApiKey: 'hunter2', useShodan: true),
          httpClient: gistApis(shodanStatus: 500));
      final shodan = result.errors.where((e) => e.source == 'Shodan');
      expect(shodan, hasLength(3)); // one per resolved IP
      expect(shodan.first.url.toString(),
          'https://api.shodan.io/shodan/host/13.234.210.38');
      expect(result.toJsonString(), isNot(contains('hunter2')));
      // the other sources are still filled
      expect(result.data!['virustotal'], isNotNull);
      expect(result.data!['whois'], isNotNull);
    });

    test('tolerated 404 (Shodan: IP unknown) is no error', () async {
      final result = await lookup('gist.github.com',
          config: WtfisConfig(
              vtApiKey: 'foo', shodanApiKey: 'hunter2', useShodan: true),
          httpClient: gistApis(shodanStatus: 404));
      expect(result.ok, isTrue);
    });

    test('network errors are collected', () async {
      final result = await lookup('gist.github.com',
          config: WtfisConfig(vtApiKey: 'foo'),
          httpClient: MockClient(
              (req) async => throw http.ClientException('Connection refused')));
      expect(result.ok, isFalse);
      expect(result.aborted, isFalse);
      expect(result.errors.map((e) => e.kind),
          everyElement(LookupErrorKind.network));
      expect(result.errors.first.message, 'Connection refused');
    });

    test('invalid API data is collected as model error', () async {
      final out = jsonDecode(await lookupDomain('gist.github.com',
          config: WtfisConfig(vtApiKey: 'foo'),
          httpClient:
              gistApis(vtDomainBody: {'intentionally': 'wrong data'})));
      final errors = out['errors'] as List;
      expect(errors, hasLength(1));
      expect(errors[0]['type'], 'model');
      expect(errors[0]['source'], 'Virustotal');
      expect(errors[0]['message'], startsWith('Data model validation error'));
      // the remaining sources are still returned
      expect(out['virustotal'], isNull);
      expect(out['resolutions'], isNotNull);
      expect(out['whois'], isNotNull);
    });

    test('rejects IP addresses with an input error', () async {
      final result = await lookup('1.1.1.1', config: WtfisConfig());
      expect(result.aborted, isTrue);
      expect(result.errors.single.kind, LookupErrorKind.input);
      expect(result.toJson()['errors'][0]['type'], 'input');
    });

    test('invalid config is reported instead of thrown', () async {
      final result = await lookup('example.com',
          config: WtfisConfig(maxResolutions: 11), httpClient: gistApis());
      expect(result.aborted, isTrue);
      expect(result.errors.single.kind, LookupErrorKind.config);
    });

    test('pretty output is indented', () async {
      final json = await lookupDomain('example.com',
          config: WtfisConfig(), httpClient: gistApis(), pretty: true);
      expect(json, startsWith('{\n  "entity": "example.com"'));
    });
  });

  group('config', () {
    test('fromEnvironment reads keys and WTFIS_DEFAULTS', () {
      final c = WtfisConfig.fromEnvironment(
        environment: {
          'VT_API_KEY': 'foo',
          'SHODAN_API_KEY': 'hunter2',
          'GEOLOCATION_SERVICE': 'ipinfo',
          'WTFIS_DEFAULTS': '-s -u',
        },
        envFile: 'does-not-exist',
      );
      expect(c.vtApiKey, 'foo');
      expect(c.useShodan, isTrue);
      expect(c.useUrlHaus, isTrue);
      expect(c.geolocationService, 'ipinfo');
    });

    test('validations', () {
      expect(WtfisConfig().validate(), isEmpty);
      expect(WtfisConfig(maxResolutions: 11).validate(), hasLength(1));
      expect(WtfisConfig(geolocationService: 'foo').validate(), hasLength(1));
      expect(WtfisConfig(geolocationService: 'ip2location').validate(),
          hasLength(1));
      expect(
          WtfisConfig(maxResolutions: -1, geolocationService: 'foo')
              .validate()
              .map((e) => e.kind),
          [LookupErrorKind.config, LookupErrorKind.config]);
    });
  });

  group('models', () {
    test('VT domain requires data', () {
      expect(() => VtDomain.fromJson({'intentionally': 'wrong data'}),
          throwsA(isA<ModelException>()));
    });

    test('resolutions ipList', () {
      final r = Resolutions.fromJson(testData('vt_resolutions_gist.json'));
      expect(r.count, 37);
      expect(r.data, hasLength(10));
      expect(r.data[1].ipAddressLastAnalysisStats.malicious, 1);
      expect(r.ipList(2), ['13.234.210.38', '192.30.255.113']);
    });

    test('empty VT whois', () {
      final w = Whois.fromVirustotal({'data': []});
      expect(w.source, 'virustotal');
      expect(w.domain, '');
    });

    test('ipinfo special fields', () {
      final m = IpGeoAsn.fromIpInfo(
          Map.from((testData('ipinfo_1.1.1.1.json') as Map)['1.1.1.1']));
      expect(m.hostname, 'one.one.one.one');
      expect(m.isAnycast, 'True');
      expect(m.asn, '13335');
      expect(m.org, 'Cloudflare, Inc.');
      expect(m.link, 'https://ipinfo.io/1.1.1.1');
    });

    test('ip2location special fields', () {
      final m = IpGeoAsn.fromIp2Location(
          Map.from((testData('ip2location_1.1.1.1.json') as Map)['1.1.1.1']));
      expect(m.isProxy, 'False');
      expect(m.city, 'Brisbane');
      expect(m.org, 'CloudFlare Inc.');
    });

    test('abuseipdb', () {
      final m = AbuseIpDb.fromJson(
          Map.from((testData('abuseipdb_1.1.1.1_raw.json') as Map)['data']));
      expect(m.abuseConfidenceScore, 100);
      expect(m.toJson()['last_reported_at'], '2018-12-20T20:55:14Z');
    });
  });

  group('utils', () {
    test('refang', () {
      expect(refang('www[.]example[.]com'), 'www.example.com');
    });

    test('isIp', () {
      expect(isIp('1.1.1.1'), isTrue);
      expect(isIp('1[.]1[.]1[.]1'), isTrue);
      expect(isIp('10.0.0.1'), isFalse);
      expect(isIp('192.168.1.1'), isFalse);
      expect(isIp('2606:4700:4700::1111'), isTrue);
      expect(isIp('::1'), isFalse);
      expect(isIp('example.com'), isFalse);
    });

    test('standardizeTimestamp', () {
      expect(standardizeTimestamp(null), isNull);
      expect(standardizeTimestamp(1660428388), '2022-08-13T22:06:28Z');
      expect(standardizeTimestamp('1660428388'), '2022-08-13T22:06:28Z');
      expect(
          standardizeTimestamp('2022-08-13T22:06:28Z'), '2022-08-13T22:06:28Z');
      expect(standardizeTimestamp('2007-10-09T18:20:50+0000'),
          '2007-10-09T18:20:50Z');
      expect(
          standardizeTimestamp('2022-08-13 22:06:28'), '2022-08-13 22:06:28');
      expect(standardizeTimestamp('not a date'), 'not a date');
    });
  });
}
