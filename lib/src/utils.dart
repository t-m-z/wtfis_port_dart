import 'dart:io' show InternetAddress, InternetAddressType;

import 'exceptions.dart';

/// Strip `[]`s out of text (e.g. `example[.]com` -> `example.com`).
String refang(String text) => text.replaceAll('[', '').replaceAll(']', '');

/// Whether [text] is a globally routable IPv4/IPv6 address
/// (mirrors Python's `ipaddress.ip_address(...).is_global`).
bool isIp(String text) {
  final addr = InternetAddress.tryParse(refang(text));
  if (addr == null) return false;
  final b = addr.rawAddress;
  if (addr.type == InternetAddressType.IPv4) {
    bool inNet(List<int> net, int prefix) {
      var bits = prefix;
      for (var i = 0; i < 4 && bits > 0; i++) {
        final mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
        if ((b[i] & mask) != (net[i] & mask)) return false;
        bits -= 8;
      }
      return true;
    }

    const nonGlobal = <(List<int>, int)>[
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
    return !nonGlobal.any((n) => inNet(n.$1, n.$2));
  }
  // IPv6: loopback, unspecified, link-local, unique-local, multicast,
  // documentation range are not global.
  if (addr.isLoopback || addr.isLinkLocal || addr.isMulticast) return false;
  if (b.every((x) => x == 0)) return false;
  if ((b[0] & 0xfe) == 0xfc) return false;
  if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) {
    return false;
  }
  return true;
}

/// Lazy conversion to string (port of the pydantic `LaxStr` validator).
String? laxStr(Object? v) {
  if (v == null) return null;
  if (v is String) return v;
  if (v is num) return v.toString();
  if (v is bool) return v ? 'True' : 'False';
  throw const ModelException('Cannot be cast to string');
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
String? standardizeTimestamp(Object? ts) {
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
