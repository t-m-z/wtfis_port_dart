import '../exceptions.dart';

typedef Json = Map<String, dynamic>;

/// Helpers that read typed values from decoded JSON and raise a
/// [ModelException] (the pydantic ValidationError equivalent) on mismatch.
T req<T>(Json json, String key, String model) {
  if (!json.containsKey(key) || json[key] == null) {
    throw ModelException('$model: field "$key" required');
  }
  return opt<T>(json, key, model) as T;
}

T? opt<T>(Json json, String key, String model) {
  final v = json[key];
  if (v == null) return null;
  if (v is T) return v;
  throw ModelException(
      '$model: field "$key" expected $T, got ${v.runtimeType}');
}

Json reqMap(Json json, String key, String model) =>
    Map<String, dynamic>.from(req<Map>(json, key, model));

Json? optMap(Json json, String key, String model) {
  final v = opt<Map>(json, key, model);
  return v == null ? null : Map<String, dynamic>.from(v);
}

List<T> listOf<T>(Json json, String key, String model,
    {bool required = false}) {
  final v =
      required ? req<List>(json, key, model) : opt<List>(json, key, model);
  if (v == null) return <T>[];
  try {
    return v.cast<T>().toList();
  } on TypeError {
    throw ModelException('$model: field "$key" expected List<$T>');
  }
}
