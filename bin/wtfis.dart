import 'dart:io';

import 'package:args/args.dart';

import 'src/config.dart';
import 'src/lookup.dart';
import 'src/lookup_result.dart';

/// Exit codes: 0 = no errors, 1 = lookup done but some sources failed
/// (see `"errors"`), 64 = invalid usage, input or configuration.
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

  final ArgResults args;
  try {
    args = parser.parse(arguments);
  } on FormatException catch (e) {
    // thrown by package:args for unknown options
    stderr.writeln('${e.message}\n\n${parser.usage}');
    exitCode = 64;
    return;
  }
  if (args.flag('help') || args.rest.length != 1) {
    stdout.writeln('Usage: wtfis [options] <domain>\n\n${parser.usage}');
    exitCode = args.flag('help') ? 0 : 64;
    return;
  }

  final maxResolutions = int.tryParse(args.option('max-resolutions')!);
  if (maxResolutions == null) {
    stderr.writeln('--max-resolutions must be an integer\n\n${parser.usage}');
    exitCode = 64;
    return;
  }

  LookupResult result;
  try {
    final config = WtfisConfig.fromEnvironment(
      all: args.flag('all'),
      useShodan: args.flag('use-shodan'),
      useGreynoise: args.flag('use-greynoise'),
      useAbuseIpDb: args.flag('use-abuseipdb'),
      useUrlHaus: args.flag('use-urlhaus'),
      maxResolutions: maxResolutions,
      geolocationService: args.option('geolocation-service'),
    );
    result = await lookup(args.rest.single, config: config);
  } on FileSystemException catch (e) {
    // ~/.env.wtfis exists but cannot be read
    result = LookupResult(args.rest.single, errors: [
      LookupError(LookupErrorKind.config, 'config',
          'Cannot read ${e.path ?? 'env file'}: ${e.message}'),
    ]);
  }

  stdout.writeln(result.toJsonString(pretty: args.flag('pretty')));
  for (final e in result.errors) {
    stderr.writeln('Error: $e');
  }
  exitCode = result.ok
      ? 0
      : result.aborted
          ? 64
          : 1;
}
