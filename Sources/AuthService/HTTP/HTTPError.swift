enum HTTPError: Error {
    case badRequest(String)
    case conflict(String)
    case forbidden(String)
    case unauthorized(String)
    case notFound(String)
    case internalServerError(String)

    var statusCode: Int {
        switch self {
        case .badRequest:
            400
        case .conflict:
            409
        case .forbidden:
            403
        case .unauthorized:
            401
        case .notFound:
            404
        case .internalServerError:
            500
        }
    }

    var message: String {
        switch self {
        case .badRequest(let message),
             .conflict(let message),
             .forbidden(let message),
             .unauthorized(let message),
             .notFound(let message),
             .internalServerError(let message):
            message
        }
    }
}
