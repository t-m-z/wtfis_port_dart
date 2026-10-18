import 'dart:io';

import 'package:args/args.dart';

import 'src/config.dart';
import 'src/exceptions.dart';
import 'src/lookup.dart';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser()
    ..addFlag('all',
        abbr: 'A', negatable: false, help: 'Enable all possible enrichments')
    ..addFlag('use-shodan',
        abbr: 's', negatable: false, help: 'Use Shodan to enrich IPs')
    ..addFlag('use-greynoise',
        abbr: 'g', negatable: false, help: 'Enable Greynoise for IPs')
    ..addFlag('use-abuseipdb',
        abbr: 'a', negatable: false, help: 'Enable AbuseIPDB for IPs')
    ..addFlag('use-urlhaus',
        abbr: 'u', negatable: false, help: 'Enable URLhaus for domains')
    ..addOption('max-resolutions',
        abbr: 'm',
        valueHelp: 'N',
        defaultsTo: '3',
        help: 'Maximum number of resolutions to show')
    ..addOption('geolocation-service',
        allowed: ['ip2location', 'ipinfo', 'ipwhois'],
        help: 'Geolocation service to use (default: ipwhois)')
    ..addFlag('pretty',
        abbr: 'p', negatable: false, help: 'Pretty-print the JSON output')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help');

  try {
    final args = parser.parse(arguments);
    if (args.flag('help') || args.rest.length != 1) {
      stdout.writeln('Usage: wtfis [options] <domain>\n\n${parser.usage}');
      exitCode = args.flag('help') ? 0 : 64;
      return;
    }

    final maxResolutions = int.tryParse(args.option('max-resolutions')!);
    if (maxResolutions == null) {
      throw const FormatException('--max-resolutions must be an integer');
    }
    final config = WtfisConfig.fromEnvironment(
      all: args.flag('all'),
      useShodan: args.flag('use-shodan'),
      useGreynoise: args.flag('use-greynoise'),
      useAbuseIpDb: args.flag('use-abuseipdb'),
      useUrlHaus: args.flag('use-urlhaus'),
      maxResolutions: maxResolutions,
      geolocationService: args.option('geolocation-service'),
    );

    stdout.writeln(await lookupDomain(args.rest.single,
        config: config, pretty: args.flag('pretty')));
  } on FormatException catch (e) {
    stderr.writeln('${e.message}\n\n${parser.usage}');
    exitCode = 64;
  } on ArgumentError catch (e) {
    stderr.writeln(
        'Error: ${e.message}${e.invalidValue != null ? ' (${e.invalidValue})' : ''}');
    exitCode = 64;
  } on WtfisException catch (e) {
    stderr.writeln(e);
    exitCode = 1;
  }
}
