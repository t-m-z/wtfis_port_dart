part of 'lookup.dart';

/// Strip `[]`s out of text (e.g. `example[.]com` -> `example.com`).
String _refang(String text) => text.replaceAll('[', '').replaceAll(']', '');

/// An IPv4 or IPv6 address as raw bytes (4 or 16).
///
/// Own implementation instead of `InternetAddress` from `dart:io`, which is
/// not available on the web.
class _IpAddress {
  final List<int> bytes;

  const _IpAddress(this.bytes);

  bool get isV4 => bytes.length == 4;

  /// Canonical notation: dotted decimal for IPv4, RFC 5952 for IPv6
  /// (lowercase, no leading zeros, longest zero run as `::`).
  String get address {
    if (isV4) return bytes.join('.');
    final groups = [
      for (var i = 0; i < 16; i += 2) (bytes[i] << 8) | bytes[i + 1],
    ];
    // longest run of at least two zero groups (first one wins on a tie)
    var bestStart = -1, bestLen = 1;
    for (var i = 0; i < 8;) {
      if (groups[i] != 0) {
        i++;
        continue;
      }
      var j = i;
      while (j < 8 && groups[j] == 0) {
        j++;
      }
      if (j - i > bestLen) {
        bestStart = i;
        bestLen = j - i;
      }
      i = j;
    }
    String hex(Iterable<int> g) => g.map((x) => x.toRadixString(16)).join(':');
    if (bestStart < 0) return hex(groups);
    return '${hex(groups.take(bestStart))}::'
        '${hex(groups.skip(bestStart + bestLen))}';
  }
}

final _ipv4Part = RegExp(r'^(0|[1-9][0-9]{0,2})$');
final _ipv6Group = RegExp(r'^[0-9a-fA-F]{1,4}$');

List<int>? _parseIpv4(String s) {
  final parts = s.split('.');
  if (parts.length != 4) return null;
  final result = <int>[];
  for (final p in parts) {
    if (!_ipv4Part.hasMatch(p)) return null;
    final v = int.parse(p);
    if (v > 255) return null;
    result.add(v);
  }
  return result;
}

List<int>? _parseIpv6(String s) {
  if (!s.contains(':')) return null;
  final halves = s.split('::');
  if (halves.length > 2) return null;

  // Groups of one side; the last group may be an embedded IPv4 address
  List<int>? side(String part, {required bool allowV4}) {
    if (part.isEmpty) return <int>[];
    final result = <int>[];
    final groups = part.split(':');
    for (var i = 0; i < groups.length; i++) {
      final g = groups[i];
      if (allowV4 && i == groups.length - 1 && g.contains('.')) {
        final v4 = _parseIpv4(g);
        if (v4 == null) return null;
        result.addAll(v4);
      } else if (_ipv6Group.hasMatch(g)) {
        final v = int.parse(g, radix: 16);
        result.addAll([v >> 8, v & 0xff]);
      } else {
        return null;
      }
    }
    return result;
  }

  if (halves.length == 1) {
    final all = side(s, allowV4: true);
    return all != null && all.length == 16 ? all : null;
  }
  final head = side(halves[0], allowV4: false);
  final tail = side(halves[1], allowV4: true);
  if (head == null || tail == null) return null;
  final missing = 16 - head.length - tail.length;
  // "::" stands for at least one zero group
  if (missing < 2) return null;
  return [...head, ...List<int>.filled(missing, 0), ...tail];
}

/// Parses [text] (defanged and `[...]` allowed) as IPv4 or IPv6 address,
/// or `null` if it is no IP address at all.
_IpAddress? _parseIp(String text) {
  final s = _refang(text).trim();
  if (s.isEmpty) return null;
  final bytes = _parseIpv4(s) ?? _parseIpv6(s);
  return bytes == null ? null : _IpAddress(bytes);
}

/// Whether [text] is a globally routable IPv4/IPv6 address (like Python's
/// `ipaddress.ip_address(...).is_global`, but multicast addresses are not
/// considered public either).
bool _isIp(String text) {
  final addr = _parseIp(text);
  return addr != null && _isGlobal(addr);
}

const _nonGlobalV4 = <(List<int>, int)>[
  ([0, 0, 0, 0], 8),
  ([10, 0, 0, 0], 8),
  ([100, 64, 0, 0], 10),
  ([127, 0, 0, 0], 8),
  ([169, 254, 0, 0], 16),
  ([172, 16, 0, 0], 12),
  ([192, 0, 0, 0], 24),
  ([192, 0, 2, 0], 24),
  ([192, 168, 0, 0], 16),
  ([198, 18, 0, 0], 15),
  ([198, 51, 100, 0], 24),
  ([203, 0, 113, 0], 24),
  ([224, 0, 0, 0], 4),
  ([240, 0, 0, 0], 4),
];

bool _inNet(List<int> b, List<int> net, int prefix) {
  var bits = prefix;
  for (var i = 0; i < net.length && bits > 0; i++) {
    final mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((b[i] & mask) != (net[i] & mask)) return false;
    bits -= 8;
  }
  return true;
}

bool _isGlobal(_IpAddress addr) {
  final b = addr.bytes;
  if (addr.isV4) {
    return !_nonGlobalV4.any((n) => _inNet(b, n.$1, n.$2));
  }
  // IPv4-mapped (::ffff:a.b.c.d): decided by the IPv4 address
  if (_inNet(b, const [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96)) {
    return _isGlobal(_IpAddress(b.sublist(12)));
  }
  // unspecified (::), loopback (::1)
  if (b.take(15).every((x) => x == 0) && b[15] <= 1) return false;
  if ((b[0] & 0xfe) == 0xfc) return false; // unique local fc00::/7
  if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false; // fe80::/10
  if (b[0] == 0xff) return false; // multicast ff00::/8
  if (_inNet(b, const [0x20, 0x01, 0x0d, 0xb8], 32)) return false; // doc
  return true;
}

/// Lazy conversion to string (port of the pydantic `LaxStr` validator).
String? _laxStr(Object? v) {
  if (v == null) return null;
  if (v is String) return v;
  if (v is num) return v.toString();
  if (v is bool) return v ? 'True' : 'False';
  throw const _ModelException('Cannot be cast to string');
}

String _pad(int n, [int width = 2]) => n.toString().padLeft(width, '0');

String _fmtUtc(DateTime dt) {
  final u = dt.toUtc();
  return '${_pad(u.year, 4)}-${_pad(u.month)}-${_pad(u.day)}'
      'T${_pad(u.hour)}:${_pad(u.minute)}:${_pad(u.second)}Z';
}

final _stdUtc = RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$');
final _noTz = RegExp(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$');
final _compactOffset = RegExp(r'([+-]\d{2})(\d{2})$');

/// Convert any timestamp (epoch int / epoch string / ISO-ish string) to the
/// standard format `YYYY-MM-DDTHH:MM:SSZ` (port of `utils.Timestamp`).
/// Returns the input unchanged if it cannot be converted (fail open).
String? _standardizeTimestamp(Object? ts) {
  if (ts == null) return null;
  final s = ts.toString();
  if (_stdUtc.hasMatch(s)) return s;

  final epoch = ts is int ? ts : int.tryParse(s);
  if (epoch != null) {
    return _fmtUtc(
        DateTime.fromMillisecondsSinceEpoch(epoch * 1000, isUtc: true));
  }

  // No explicit timezone - return date as is
  if (_noTz.hasMatch(s)) return s;

  // "+0000" -> "+00:00" so DateTime.parse accepts it
  final normalized =
      s.replaceFirstMapped(_compactOffset, (m) => '${m[1]}:${m[2]}');
  final parsed = DateTime.tryParse(normalized);
  if (parsed == null) return s;
  // Python's naive datetimes are interpreted as local time
  return _fmtUtc(parsed);
}
