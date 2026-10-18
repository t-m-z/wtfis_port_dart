part of 'lookup.dart';

/// Raised by the model constructors when API data does not match the
/// expected data model (the pydantic ValidationError equivalent).
///
/// It never leaves the clients: [_BaseClient.parse] turns it into a
/// `LookupError` of kind `model`.
class _ModelException implements Exception {
  final String message;
  const _ModelException(this.message);

  @override
  String toString() => message;
}
