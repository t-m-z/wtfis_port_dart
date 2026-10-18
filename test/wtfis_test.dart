import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import '../bin/src/lookup.dart';

dynamic testData(String name) =>
    jsonDecode(File('test/test_data/$name').readAsStringSync());

/// Runs [lookup] with the given environment only (never the real process
/// environment or ~/.env.wtfis).
Future run(
  String domain, {
  Map<String, String> env = const {},
  http.Client? client,
  bool all = false,
  bool useShodan = false,
  int maxResolutions = 3,
  String? geolocationService,
}) =>
    lookup(domain,
        environment: env,
        envFile: 'test/test_data/does-not-exist',
        httpClient: client ?? gistApis(),
        all: all,
        useShodan: useShodan,
        maxResolutions: maxResolutions,
        geolocationService: geolocationService);

/// Same as [run], returning the decoded JSON output.
Future<Map<String, dynamic>> runJson(
  String domain, {
  Map<String, String> env = const {},
  http.Client? client,
  bool all = false,
  int maxResolutions = 3,
}) async =>
    jsonDecode((await run(domain,
            env: env,
            client: client,
            all: all,
            maxResolutions: maxResolutions))
        .toJsonString()) as Map<String, dynamic>;

const vt = {'VT_API_KEY': 'foo'};

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
  final ipinfo = testData('ipinfo_gist.json') as Map;
  final ip2location = testData('ip2location_gist.json') as Map;
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
      case 'ipinfo.io':
        return jsonResponse(ipinfo[url.pathSegments.first]);
      case 'api.ip2location.io':
        expect(url.queryParameters['key'], 'bob');
        return jsonResponse(ip2location[url.queryParameters['ip']]);
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
  group('lookup', () {
    test('returns enriched data (VT + IPWhois + VT whois)', () async {
      final out = await runJson('gist[.]github[.]com', env: vt);

      expect(out['entity'], 'gist.github.com');
      expect(out['type'], 'domain');
      expect(out['ok'], isTrue);
      expect(out['errors'], isEmpty);

      final v = out['virustotal'];
      expect(v['id'], 'gist.github.com');
      expect(v['last_analysis_stats'], {
        'harmless': 84,
        'malicious': 0,
        'suspicious': 0,
        'timeout': 0,
        'undetected': 10,
      });
      expect(v['malicious_vendors'], isEmpty);
      expect(v['categories'], [
        'advice',
        'file sharing/storage',
        'information technology',
        'media sharing',
        'social networks',
      ]);
      expect(
          v['popularity_ranks'], {'Majestic': 532, 'Cisco Umbrella': 39463});
      expect(v['creation_date'], '2007-10-09T18:20:50Z');

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

    test('result object offers data and errors', () async {
      final result = await run('gist.github.com', env: vt);
      expect(result.entity, 'gist.github.com');
      expect(result.ok, isTrue);
      expect(result.aborted, isFalse);
      expect(result.data['virustotal'], isNotNull);
      expect(result.toJsonString(pretty: true),
          startsWith('{\n  "entity": "gist.github.com"'));
    });

    test('uses IP2Whois when its key is set, plus Shodan and URLhaus',
        () async {
      final out = await runJson('gist.github.com',
          env: {
            ...vt,
            'IP2WHOIS_API_KEY': 'alice',
            'SHODAN_API_KEY': 'hunter2',
            'URLHAUS_API_KEY': 'eve',
          },
          all: true);

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

    test('IPinfo as geolocation service', () async {
      final result = await run('gist.github.com',
          env: vt, geolocationService: 'ipinfo');
      expect(result.ok, isTrue);
      final geo = result.data['resolutions']['data'][0]['geoasn'];
      expect(geo['source'], 'IPinfo');
      expect(geo['asn'], '16509');
      expect(geo['city'], 'Mumbai');
    });

    test('IP2Location as geolocation service', () async {
      final result = await run('gist.github.com',
          env: {...vt, 'IP2LOCATION_API_KEY': 'bob'},
          geolocationService: 'ip2location');
      expect(result.ok, isTrue);
      final geo = result.data['resolutions']['data'][0]['geoasn'];
      expect(geo['source'], 'IP2Location');
      expect(geo['city'], 'Mumbai');
    });

    test('reads API keys, GEOLOCATION_SERVICE and WTFIS_DEFAULTS', () async {
      final requests = <Uri>[];
      await run('gist.github.com',
          env: {
            ...vt,
            'SHODAN_API_KEY': 'hunter2',
            'GEOLOCATION_SERVICE': 'ipinfo',
            'WTFIS_DEFAULTS': '-s',
          },
          client: gistApis(requests: requests));
      final hosts = requests.map((u) => u.host).toSet();
      expect(hosts, containsAll(['ipinfo.io', 'api.shodan.io']));
      expect(hosts, isNot(contains('ipwho.is')));
    });

    test('without any API key nothing is requested', () async {
      final requests = <Uri>[];
      final out = await runJson('example.com',
          client: gistApis(requests: requests));
      expect(requests, isEmpty);
      expect(out['ok'], isTrue);
      expect(out['virustotal'], isNull);
      expect(out['resolutions'], isNull);
      expect(out['whois'], isNull);
    });

    test('maxResolutions = 0 skips resolutions and IP enrichment', () async {
      final requests = <Uri>[];
      final out = await runJson('gist.github.com',
          env: vt, maxResolutions: 0, client: gistApis(requests: requests));
      expect(out['resolutions'], isNull);
      expect(requests.where((u) => u.host == 'ipwho.is'), isEmpty);
      expect(out['virustotal'], isNotNull);
      expect(out['whois'], isNotNull);
    });
  });

  group('errors', () {
    test('HTTP errors are collected with status, url and body', () async {
      final out = await runJson('gist.github.com',
          env: vt, client: gistApis(vtStatus: 401));
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
      final result = await run('gist.github.com',
          env: vt, client: gistApis(vtStatus: 502, vtErrorBody: page));
      final e = result.httpErrors.first;
      expect(e.statusCode, 502);
      expect(e.message, startsWith('502 Server Error'));
      expect(e.body, startsWith('<html><body><h1>502 Bad Gateway</h1>'));
      expect(e.body.length, 1001); // 1000 characters + ellipsis
    });

    test('API keys in query parameters are not part of error urls', () async {
      final result = await run('gist.github.com',
          env: {...vt, 'SHODAN_API_KEY': 'hunter2'},
          useShodan: true,
          client: gistApis(shodanStatus: 500));
      final shodan = result.errors.where((e) => e.source == 'Shodan');
      expect(shodan, hasLength(3)); // one per resolved IP
      expect(shodan.first.url.toString(),
          'https://api.shodan.io/shodan/host/13.234.210.38');
      expect(result.toJsonString(), isNot(contains('hunter2')));
      // the other sources are still filled
      expect(result.data['virustotal'], isNotNull);
      expect(result.data['whois'], isNotNull);
    });

    test('tolerated 404 (Shodan: IP unknown) is no error', () async {
      final result = await run('gist.github.com',
          env: {...vt, 'SHODAN_API_KEY': 'hunter2'},
          useShodan: true,
          client: gistApis(shodanStatus: 404));
      expect(result.ok, isTrue);
    });

    test('network errors are collected', () async {
      final result = await run('gist.github.com',
          env: vt,
          client: MockClient(
              (req) async => throw http.ClientException('Connection refused')));
      expect(result.ok, isFalse);
      expect(result.aborted, isFalse);
      expect(result.errors.map((e) => e.kind.name), everyElement('network'));
      expect(result.errors.first.message, 'Connection refused');
    });

    test('invalid API data is collected as model error', () async {
      final out = await runJson('gist.github.com',
          env: vt,
          client: gistApis(vtDomainBody: {'intentionally': 'wrong data'}));
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

    for (final ip in ['1.1.1.1', '1[.]1[.]1[.]1', '2606:4700:4700::1111']) {
      test('rejects IP address $ip with an input error', () async {
        final result = await run(ip);
        expect(result.aborted, isTrue);
        expect(result.errors.single.kind.name, 'input');
        expect(result.toJson()['errors'][0]['type'], 'input');
      });
    }

    test('rejects empty input', () async {
      final result = await run('  ');
      expect(result.errors.single.kind.name, 'input');
    });

    test('invalid config is reported instead of thrown', () async {
      for (final r in [
        await run('example.com', maxResolutions: 11),
        await run('example.com', maxResolutions: -1),
        await run('example.com', geolocationService: 'foo'),
        // ip2location without IP2LOCATION_API_KEY
        await run('example.com', geolocationService: 'ip2location'),
      ]) {
        expect(r.aborted, isTrue);
        expect(r.errors.single.kind.name, 'config');
        expect(r.errors.single.source, 'config');
      }
    });
  });
}
