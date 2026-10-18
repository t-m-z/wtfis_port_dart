import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import '../wtfis/lookup.dart';

dynamic testData(String name) =>
    jsonDecode(File('test/test_data/$name').readAsStringSync());

/// Runs [lookup] with API keys given by their wtfis environment variable
/// names (`VT_API_KEY`, ...).
Future<LookupResult> run(
  String address, {
  Map<String, String> keys = const {},
  http.Client? client,
  int maxResolutions = 3,
  String geolocationService = 'ipwhois',
}) =>
    lookup(address,
        vtApiKey: keys['VT_API_KEY'],
        ip2WhoisApiKey: keys['IP2WHOIS_API_KEY'],
        ip2LocationApiKey: keys['IP2LOCATION_API_KEY'],
        shodanApiKey: keys['SHODAN_API_KEY'],
        greynoiseApiKey: keys['GREYNOISE_API_KEY'],
        abuseIpDbApiKey: keys['ABUSEIPDB_API_KEY'],
        urlHausApiKey: keys['URLHAUS_API_KEY'],
        geolocationService: geolocationService,
        maxResolutions: maxResolutions,
        httpClient: client ?? gistApis());

/// Same as [run], returning the decoded JSON output.
Future<Map<String, dynamic>> runJson(
  String address, {
  Map<String, String> keys = const {},
  http.Client? client,
  int maxResolutions = 3,
}) async =>
    jsonDecode((await run(address,
            keys: keys, client: client, maxResolutions: maxResolutions))
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

/// Mock of all APIs serving the "1.1.1.1" fixtures (for any queried IP).
MockClient ipApis({List<Uri>? requests, int? status}) {
  Object? one(String file) => (testData(file) as Map)['1.1.1.1'];
  return MockClient((req) async {
    requests?.add(req.url);
    if (status != null) {
      return http.Response('<html><body>Service Unavailable</body></html>',
          status,
          headers: {'content-type': 'text/html'});
    }
    final url = req.url;
    switch (url.host) {
      case 'www.virustotal.com':
        return url.path.endsWith('/historical_whois')
            ? jsonResponse(testData('vt_whois_1.1.1.1.json'))
            : jsonResponse(testData('vt_ip_1.1.1.1.json'));
      case 'ipwho.is':
        return jsonResponse(one('ipwhois_1.1.1.1.json'));
      case 'api.shodan.io':
        return jsonResponse(one('shodan_1.1.1.1.json'));
      case 'api.greynoise.io':
        return jsonResponse(one('greynoise_1.1.1.1.json'));
      case 'api.abuseipdb.com':
        return jsonResponse(testData('abuseipdb_1.1.1.1_raw.json'));
      case 'urlhaus-api.abuse.ch':
        return jsonResponse(one('urlhaus_1.1.1.1.json'));
    }
    return http.Response('not found', 404);
  });
}

const allKeys = {
  'VT_API_KEY': 'foo',
  'IP2WHOIS_API_KEY': 'alice',
  'SHODAN_API_KEY': 'hunter2',
  'GREYNOISE_API_KEY': 'carol',
  'ABUSEIPDB_API_KEY': 'dave',
  'URLHAUS_API_KEY': 'eve',
};

void main() {
  group('lookup', () {
    test('returns enriched data (VT + IPWhois + VT whois)', () async {
      final out = await runJson('gist[.]github[.]com', keys: vt);

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
      final result = await run('gist.github.com', keys: vt);
      expect(result.entity, 'gist.github.com');
      expect(result.type, 'domain');
      expect(result.ok, isTrue);
      expect(result.aborted, isFalse);
      expect(result.data!['virustotal'], isNotNull);
      expect(result.toJsonString(pretty: true),
          startsWith('{\n  "entity": "gist.github.com"'));
    });

    test('uses IP2Whois when its key is set, plus Shodan and URLhaus',
        () async {
      final out = await runJson('gist.github.com',
          keys: {
            ...vt,
            'IP2WHOIS_API_KEY': 'alice',
            'SHODAN_API_KEY': 'hunter2',
            'URLHAUS_API_KEY': 'eve',
          });

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
          keys: vt, geolocationService: 'ipinfo');
      expect(result.ok, isTrue);
      final geo = result.data!['resolutions']['data'][0]['geoasn'];
      expect(geo['source'], 'IPinfo');
      expect(geo['asn'], '16509');
      expect(geo['city'], 'Mumbai');
    });

    test('IP2Location as geolocation service', () async {
      final result = await run('gist.github.com',
          keys: {...vt, 'IP2LOCATION_API_KEY': 'bob'},
          geolocationService: 'ip2location');
      expect(result.ok, isTrue);
      final geo = result.data!['resolutions']['data'][0]['geoasn'];
      expect(geo['source'], 'IP2Location');
      expect(geo['city'], 'Mumbai');
    });

    test('every source with an API key is queried, others are skipped',
        () async {
      final requests = <Uri>[];
      await run('gist.github.com',
          keys: {...vt, 'SHODAN_API_KEY': 'hunter2'},
          geolocationService: 'ipinfo',
          client: gistApis(requests: requests));
      final hosts = requests.map((u) => u.host).toSet();
      expect(hosts, {'www.virustotal.com', 'ipinfo.io', 'api.shodan.io'});
    });

    test('blank API keys count as not set', () async {
      final requests = <Uri>[];
      final result = await lookup('gist.github.com',
          vtApiKey: '  ',
          shodanApiKey: '',
          httpClient: gistApis(requests: requests));
      expect(requests, isEmpty);
      expect(result.ok, isTrue);
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
          keys: vt, maxResolutions: 0, client: gistApis(requests: requests));
      expect(out['resolutions'], isNull);
      expect(requests.where((u) => u.host == 'ipwho.is'), isEmpty);
      expect(out['virustotal'], isNotNull);
      expect(out['whois'], isNotNull);
    });
  });

  group('errors', () {
    test('HTTP errors are collected with status, url and body', () async {
      final out = await runJson('gist.github.com',
          keys: vt, client: gistApis(vtStatus: 401));
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
          keys: vt, client: gistApis(vtStatus: 502, vtErrorBody: page));
      final e = result.httpErrors.first;
      expect(e.statusCode, 502);
      expect(e.message, startsWith('502 Server Error'));
      expect(e.body, startsWith('<html><body><h1>502 Bad Gateway</h1>'));
      expect(e.body!.length, 1001); // 1000 characters + ellipsis
    });

    test('API keys in query parameters are not part of error urls', () async {
      final result = await run('gist.github.com',
          keys: {...vt, 'SHODAN_API_KEY': 'hunter2'},
          client: gistApis(shodanStatus: 500));
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
      final result = await run('gist.github.com',
          keys: {...vt, 'SHODAN_API_KEY': 'hunter2'},
          client: gistApis(shodanStatus: 404));
      expect(result.ok, isTrue);
    });

    test('network errors are collected', () async {
      final result = await run('gist.github.com',
          keys: vt,
          client: MockClient(
              (req) async => throw http.ClientException('Connection refused')));
      expect(result.ok, isFalse);
      expect(result.aborted, isFalse);
      expect(result.errors.map((e) => e.kind.name), everyElement('network'));
      expect(result.errors.first.message, 'Connection refused');
    });

    test('invalid API data is collected as model error', () async {
      final out = await runJson('gist.github.com',
          keys: vt,
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

    test('rejects empty input', () async {
      final result = await run('  ');
      expect(result.type, isNull);
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

  group('IP addresses', () {
    test('IPv4 with all sources', () async {
      final requests = <Uri>[];
      final result = await run('1.1.1.1',
          keys: allKeys, client: ipApis(requests: requests));
      expect(result.ok, isTrue, reason: '${result.errors}');
      expect(result.type, 'ip');
      expect(result.entity, '1.1.1.1');

      final out = jsonDecode(result.toJsonString()) as Map<String, dynamic>;
      expect(out['type'], 'ip');
      expect(out.containsKey('resolutions'), isFalse);

      final v = out['virustotal'];
      expect(v['id'], '1.1.1.1');
      expect(v['type'], 'ip_address');
      expect(v['link'], 'https://www.virustotal.com/gui/ip-address/1.1.1.1');
      expect(v['asn'], '13335');
      expect(v['as_owner'], 'CLOUDFLARENET');
      expect(v['network'], '1.1.1.0/24');
      expect(v['reputation'], 134);
      expect(v['last_modification_date'], '2022-09-03T06:47:04Z');

      expect(out['geoasn']['source'], 'IPWhois');
      expect(out['geoasn']['ip'], '1.1.1.1');
      expect(out['shodan']['ip'], '1.1.1.1');
      expect(out['greynoise']['ip'], '1.1.1.1');
      expect(out['greynoise']['riot'], isTrue);
      expect(out['abuseipdb']['ip_address'], '1.1.1.1');
      expect(out['abuseipdb']['abuse_confidence_score'], 100);
      expect(out['urlhaus']['host'], '1.1.1.1');
      expect(out['whois']['source'], 'virustotal');

      // IP2Whois only supports domains: VT is used for the IP whois
      expect(requests.map((u) => u.host), isNot(contains('api.ip2whois.com')));
      expect(requests.map((u) => u.path), containsAll([
        '/api/v3/ip_addresses/1.1.1.1',
        '/api/v3/ip_addresses/1.1.1.1/historical_whois',
      ]));
    });

    test('defanged IPv4', () async {
      final result =
          await run('1[.]1[.]1[.]1', keys: vt, client: ipApis());
      expect(result.entity, '1.1.1.1');
      expect(result.type, 'ip');
      expect(result.ok, isTrue);
    });

    for (final input in [
      '2606:4700:4700::1111',
      '2606:4700:4700:0:0:0:0:1111',
      '2606:4700:4700[:]:1111',
      '[2606:4700:4700::1111]',
    ]) {
      test('IPv6 $input is normalized and looked up', () async {
        final requests = <Uri>[];
        final result =
            await run(input, keys: vt, client: ipApis(requests: requests));
        expect(result.ok, isTrue, reason: '${result.errors}');
        expect(result.type, 'ip');
        expect(result.entity, '2606:4700:4700::1111');
        expect(requests.map((u) => u.path),
            contains('/api/v3/ip_addresses/2606:4700:4700::1111'));
        expect(requests.map((u) => u.toString()),
            contains('https://ipwho.is/2606:4700:4700::1111'));
        // the single queried IP is used even if the API keys it differently
        expect(result.data!['geoasn'], isNotNull);
      });
    }

    for (final input in [
      '10.0.0.1',
      '192.168.1.1',
      '127.0.0.1',
      '169.254.1.1',
      '::1',
      'fe80::1',
      'fd00::1',
      '2001:db8::1',
    ]) {
      test('non-public IP $input is an input error', () async {
        final requests = <Uri>[];
        final result =
            await run(input, keys: vt, client: ipApis(requests: requests));
        expect(requests, isEmpty);
        expect(result.aborted, isTrue);
        expect(result.type, 'ip');
        expect(result.errors.single.kind.name, 'input');
        expect(result.errors.single.message,
            startsWith('Not a public IP address'));
      });
    }

    test('maxResolutions is not applicable to IPs', () async {
      final result =
          await run('1.1.1.1', keys: vt, maxResolutions: 5, client: ipApis());
      expect(result.aborted, isTrue);
      expect(result.errors.single.kind.name, 'config');
    });

    test('HTTP errors are collected per source', () async {
      final result = await run('1.1.1.1',
          keys: allKeys, client: ipApis(status: 503));
      expect(result.ok, isFalse);
      expect(result.aborted, isFalse);
      expect(
          result.errors.map((e) => e.source).toSet(),
          containsAll([
            'IPWhois',
            'Virustotal',
            'Shodan',
            'URLhaus',
            'Greynoise',
            'AbuseIPDB',
          ]));
      expect(result.errors.map((e) => e.statusCode), everyElement(503));
      expect(result.errors.first.body, contains('Service Unavailable'));
      for (final key in allKeys.values) {
        expect(result.toJsonString(), isNot(contains(key)));
      }
    });
  });
}
