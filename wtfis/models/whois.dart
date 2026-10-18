part of '../lookup.dart';

/// Normalized WHOIS record from different sources (port of `WhoisBase`).
class _Whois {
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

  const _Whois({
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
    this.nameServers = const <String>[],
    this.dateCreated,
    this.dateChanged,
    this.dateExpires,
    this.dnssec,
    this.whoisServer,
  });

  /// Port of `models/ip2whois.py`.
  factory _Whois.fromIp2Whois(_Json json) {
    const m = 'Ip2Whois';
    final v = Map<String, dynamic>.from(json);

    // Surface registrant fields to root level
    final Object? registrant = v.remove('registrant');
    if (registrant is Map<dynamic, dynamic> && registrant.isNotEmpty) {
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
    final Object? registrar = v['registrar'];
    return _Whois(
      source: 'ip2whois',
      domain: _opt<String>(v, 'domain', m) ?? '',
      registrar: registrar is Map<dynamic, dynamic>
          ? _laxStr(registrar['name'])
          : _laxStr(registrar),
      organization: _opt<String>(v, 'organization', m),
      name: _opt<String>(v, 'name', m),
      email: _opt<String>(v, 'email', m),
      phone: _opt<String>(v, 'phone', m),
      street: _opt<String>(v, 'street_address', m),
      city: _opt<String>(v, 'city', m),
      state: _opt<String>(v, 'region', m),
      country: _opt<String>(v, 'country', m),
      postalCode: _opt<String>(v, 'zip_code', m),
      nameServers: _listOf<String>(v, 'nameservers', m),
      dateCreated: _opt<String>(v, 'create_date', m),
      dateChanged: _opt<String>(v, 'update_date', m),
      dateExpires: _opt<String>(v, 'expire_date', m),
      whoisServer: _opt<String>(v, 'whois_server', m),
      dnssec: _opt<String>(v, 'dnssec', m),
    );
  }

  /// Port of `models/virustotal.py::Whois` (historical_whois endpoint;
  /// only the latest record is used).
  factory _Whois.fromVirustotal(_Json json) {
    const m = 'VirustotalWhois';
    final records = _mapList(json, 'data', m);
    if (records.isEmpty) {
      return const _Whois(source: 'virustotal', domain: '');
    }

    // Flatten
    final attrs =
        _optMap(records.first, 'attributes', m) ?? <String, dynamic>{};
    final Object? rawWhoisMap = attrs.remove('whois_map');
    final whoisMap = rawWhoisMap == null
        ? <String, dynamic>{}
        : _asJson(rawWhoisMap, '$m: field "whois_map"');
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
      final s = _laxStr(v);
      return (s != null && s.contains('|')) ? s.split(' | ').first : s;
    }

    final ns = _opt<String>(t, 'Name Server', m);
    return _Whois(
      source: 'virustotal',
      domain: dedupe((_opt<String>(t, 'Domain Name', m) ?? '').toLowerCase()),
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
      nameServers:
          ns == null ? const <String>[] : ns.toLowerCase().split(' | '),
      dateCreated: dedupe(dateCreated),
      dateChanged: dedupe(dateChanged),
      dateExpires: dedupe(dateExpires),
      dnssec: dedupe(t['DNSSEC']),
    );
  }

  _Json toJson() => {
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
        'date_created': _standardizeTimestamp(dateCreated),
        'date_changed': _standardizeTimestamp(dateChanged),
        'date_expires': _standardizeTimestamp(dateExpires),
        'dnssec': dnssec,
        if (whoisServer != null) 'whois_server': whoisServer,
      };
}
