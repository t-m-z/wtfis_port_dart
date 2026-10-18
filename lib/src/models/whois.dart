import '../utils.dart';
import 'json.dart';

/// Normalized WHOIS record from different sources (port of `WhoisBase`).
class Whois {
  final String? source;
  final String? domain;
  final String? registrar;
  final String? organization;
  final String? name;
  final String? email;
  final String? phone;
  final String? street;
  final String? city;
  final String? state;
  final String? country;
  final String? postalCode;
  final List<String> nameServers;
  final String? dateCreated;
  final String? dateChanged;
  final String? dateExpires;
  final String? dnssec;
  final String? whoisServer;

  const Whois({
    this.source,
    this.domain,
    this.registrar,
    this.organization,
    this.name,
    this.email,
    this.phone,
    this.street,
    this.city,
    this.state,
    this.country,
    this.postalCode,
    this.nameServers = const [],
    this.dateCreated,
    this.dateChanged,
    this.dateExpires,
    this.dnssec,
    this.whoisServer,
  });

  /// Port of `models/ip2whois.py`.
  factory Whois.fromIp2Whois(Json json) {
    const m = 'Ip2Whois';
    final v = Map<String, dynamic>.from(json);

    // Surface registrant fields to root level
    final registrant = v.remove('registrant');
    if (registrant is Map && registrant.isNotEmpty) {
      for (final f in const [
        'organization',
        'name',
        'email',
        'phone',
        'street_address',
        'city',
        'region',
        'country',
        'zip_code',
      ]) {
        v[f] = registrant[f];
      }
    }

    // Convert registrar from object to simply registrar.name
    final registrar = v['registrar'];
    return Whois(
      source: 'ip2whois',
      domain: opt<String>(v, 'domain', m) ?? '',
      registrar:
          registrar is Map ? registrar['name'] as String? : laxStr(registrar),
      organization: opt<String>(v, 'organization', m),
      name: opt<String>(v, 'name', m),
      email: opt<String>(v, 'email', m),
      phone: opt<String>(v, 'phone', m),
      street: opt<String>(v, 'street_address', m),
      city: opt<String>(v, 'city', m),
      state: opt<String>(v, 'region', m),
      country: opt<String>(v, 'country', m),
      postalCode: opt<String>(v, 'zip_code', m),
      nameServers: listOf<String>(v, 'nameservers', m),
      dateCreated: opt<String>(v, 'create_date', m),
      dateChanged: opt<String>(v, 'update_date', m),
      dateExpires: opt<String>(v, 'expire_date', m),
      whoisServer: opt<String>(v, 'whois_server', m),
      dnssec: opt<String>(v, 'dnssec', m),
    );
  }

  /// Port of `models/virustotal.py::Whois` (historical_whois endpoint;
  /// only the latest record is used).
  factory Whois.fromVirustotal(Json json) {
    const m = 'VirustotalWhois';
    final data = json['data'];
    if (data is! List || data.isEmpty) {
      return const Whois(source: 'virustotal', domain: '');
    }

    // Flatten
    final attrs =
        Map<String, dynamic>.from((data.first as Map)['attributes'] ?? {});
    final whoisMap = Map<String, dynamic>.from(attrs.remove('whois_map') ?? {});
    final t = <String, dynamic>{...whoisMap, ...attrs};

    // Normalized fields with multiple possible sources
    Object? pop(List<String> keys) {
      Object? result;
      for (final k in keys) {
        final v = t.remove(k);
        if (result == null && v != null && v != '') result = v;
      }
      return result;
    }

    final dateChanged = pop(['last_updated', 'Updated Date', 'Last updated']);
    final dateCreated = pop(['Creation Date', 'Registered on']);
    final dateExpires =
        pop(['Expiry Date', 'Registry Expiry Date', 'Expiry date']);
    final name = pop(['registrant_name', 'Registrant Name']);
    final country = pop(['registrant_country', 'Registrant Country']);
    final registrar = pop(['registrar_name', 'Registrar']);

    // Port of the `dedupe_values` validator: "a | b" -> "a"
    String? dedupe(Object? v) {
      final s = laxStr(v);
      return (s != null && s.contains('|')) ? s.split(' | ').first : s;
    }

    final ns = opt<String>(t, 'Name Server', m);
    return Whois(
      source: 'virustotal',
      domain: dedupe((opt<String>(t, 'Domain Name', m) ?? '').toLowerCase()),
      registrar: dedupe(registrar),
      organization: dedupe(t['Registrant Organization']),
      name: dedupe(name),
      email: dedupe(t['Registrant Email']),
      phone: dedupe(t['Registrant Phone']),
      street: dedupe(t['Registrant Street']),
      city: dedupe(t['Registrant City']),
      state: dedupe(t['Registrant State/Province']),
      country: dedupe(country),
      postalCode: dedupe(t['Registrant Postal Code']),
      nameServers: ns == null ? const [] : ns.toLowerCase().split(' | '),
      dateCreated: dedupe(dateCreated),
      dateChanged: dedupe(dateChanged),
      dateExpires: dedupe(dateExpires),
      dnssec: dedupe(t['DNSSEC']),
    );
  }

  Json toJson() => {
        'source': source,
        'domain': domain,
        'registrar': registrar,
        'organization': organization,
        'name': name,
        'email': email,
        'phone': phone,
        'street': street,
        'city': city,
        'state': state,
        'country': country,
        'postal_code': postalCode,
        'name_servers': nameServers,
        'date_created': standardizeTimestamp(dateCreated),
        'date_changed': standardizeTimestamp(dateChanged),
        'date_expires': standardizeTimestamp(dateExpires),
        'dnssec': dnssec,
        if (whoisServer != null) 'whois_server': whoisServer,
      };
}
