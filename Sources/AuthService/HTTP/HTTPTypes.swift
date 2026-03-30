import Foundation
import NIOHTTP1

struct HTTPRequestAccumulator {
    var method: HTTPMethod = .GET
    var uri: String = "/"
    var headers: HTTPHeaders = [:]
    var body = Data()
}

struct HTTPResponsePayload {
    let status: HTTPResponseStatus
    let headers: [String: String]
    let body: Data
}
