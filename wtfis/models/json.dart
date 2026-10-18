part of '../lookup.dart';

typedef _Json = Map<String, dynamic>;

// Helpers that read typed values from decoded JSON and raise a
// [_ModelException] (the pydantic ValidationError equivalent) on mismatch.
// All conversions from `dynamic` are explicit, so the code also compiles
// with `strict-casts`, `strict-inference` and `strict-raw-types`.

T _req<T>(_Json json, String key, String model) {
  if (!json.containsKey(key) || json[key] == null) {
    throw _ModelException('$model: field "$key" required');
  }
  return _opt<T>(json, key, model) as T;
}

T? _opt<T>(_Json json, String key, String model) {
  final Object? v = json[key];
  if (v == null) return null;
  if (v is T) return v;
  throw _ModelException(
      '$model: field "$key" expected $T, got ${v.runtimeType}');
}

/// Converts a decoded JSON object (any `Map`) to [_Json].
_Json _asJson(Object? v, String what) {
  if (v is Map<dynamic, dynamic>) {
    try {
      return Map<String, dynamic>.from(v);
    } on TypeError {
      throw _ModelException('$what: expected string keys');
    }
  }
  throw _ModelException('$what: expected an object, got ${v.runtimeType}');
}

_Json _reqMap(_Json json, String key, String model) =>
    _asJson(_req<Object>(json, key, model), '$model: field "$key"');

_Json? _optMap(_Json json, String key, String model) {
  final v = json[key];
  return v == null ? null : _asJson(v, '$model: field "$key"');
}

/// Entries of the object [key] whose values are objects themselves.
Map<String, _Json> _mapOfMaps(_Json json, String key, String model) => {
      for (final e in _reqMap(json, key, model).entries)
        e.key: _asJson(e.value, '$model: field "$key.${e.key}"'),
    };

/// A list of objects; missing or `null` yields an empty list unless
/// [required].
List<_Json> _mapList(_Json json, String key, String model,
    {bool required = false}) {
  final v = required
      ? _req<List<dynamic>>(json, key, model)
      : _opt<List<dynamic>>(json, key, model);
  return [
    for (final e in v ?? const <dynamic>[]) _asJson(e, '$model: field "$key"'),
  ];
}

List<T> _listOf<T>(_Json json, String key, String model,
    {bool required = false}) {
  final v = required
      ? _req<List<dynamic>>(json, key, model)
      : _opt<List<dynamic>>(json, key, model);
  if (v == null) return <T>[];
  final result = <T>[];
  for (final e in v) {
    if (e is! T) {
      throw _ModelException('$model: field "$key" expected List<$T>');
    }
    result.add(e);
  }
  return result;
}
