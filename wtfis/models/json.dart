part of '../lookup.dart';

typedef _Json = Map<String, dynamic>;

/// Helpers that read typed values from decoded JSON and raise a
/// [_ModelException] (the pydantic ValidationError equivalent) on mismatch.
T _req<T>(_Json json, String key, String model) {
  if (!json.containsKey(key) || json[key] == null) {
    throw _ModelException('$model: field "$key" required');
  }
  return _opt<T>(json, key, model) as T;
}

T? _opt<T>(_Json json, String key, String model) {
  final v = json[key];
  if (v == null) return null;
  if (v is T) return v;
  throw _ModelException(
      '$model: field "$key" expected $T, got ${v.runtimeType}');
}

_Json _reqMap(_Json json, String key, String model) =>
    Map<String, dynamic>.from(_req<Map>(json, key, model));

_Json? _optMap(_Json json, String key, String model) {
  final v = _opt<Map>(json, key, model);
  return v == null ? null : Map<String, dynamic>.from(v);
}

List<T> _listOf<T>(_Json json, String key, String model,
    {bool required = false}) {
  final v =
      required ? _req<List>(json, key, model) : _opt<List>(json, key, model);
  if (v == null) return <T>[];
  try {
    return v.cast<T>().toList();
  } on TypeError {
    throw _ModelException('$model: field "$key" expected List<$T>');
  }
}
