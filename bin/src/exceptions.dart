/// Custom wtfis exception.
class WtfisException implements Exception {
  final String message;
  const WtfisException(this.message);

  @override
  String toString() => message;
}

/// Raised when a handler cannot process the fetched data.
class HandlerException extends WtfisException {
  const HandlerException(super.message);
}

/// Raised when API data does not match the expected data model.
class ModelException extends WtfisException {
  const ModelException(super.message);
}

/// Raised for non-2xx HTTP responses (equivalent of requests' HTTPError).
class HttpStatusException extends WtfisException {
  final int statusCode;
  final Uri url;
  final String body;

  HttpStatusException(this.statusCode, this.url, this.body)
      : super(
          '$statusCode ${statusCode >= 500 ? 'Server' : 'Client'} Error '
          'for url: ${url.replace(queryParameters: const {})}',
        );
}
