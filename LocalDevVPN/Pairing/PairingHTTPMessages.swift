//
//  PairingHTTPMessages.swift
//  LocalDevVPN
//
//  HTTP/1.1 request parsing and response building for the pairing bridge.
//  Foundation only, so the wire format can be exercised without a network stack.
//

import Foundation

/// Hard caps on what the bridge will read from a connection.
enum PairingHTTPLimits {
    static let maximumBodySize = 64 * 1024
    static let maximumRequestSize = 96 * 1024
}

// MARK: - Request / Response

struct HTTPRequest {
    let method: String
    /// Path without the query string.
    let path: String
    let query: [String: String]
    /// Header names are lowercased.
    let headers: [String: String]
    let body: Data

    func header(_ name: String) -> String? {
        headers[name.lowercased()]
    }

    var jsonBody: [String: Any]? {
        guard !body.isEmpty else { return nil }
        return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
    }
}

struct HTTPResponse {
    var status: Int
    var headers: [String: String]
    var body: Data

    init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    static func json(_ object: [String: Any], status: Int = 200) -> HTTPResponse {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8)
        return HTTPResponse(status: status, headers: ["Content-Type": "application/json; charset=utf-8"], body: data)
    }

    static func error(_ code: String, _ message: String, status: Int) -> HTTPResponse {
        json(["error": code, "message": message], status: status)
    }

    static func binary(_ data: Data, contentType: String) -> HTTPResponse {
        HTTPResponse(status: 200, headers: ["Content-Type": contentType], body: data)
    }

    static func empty(status: Int) -> HTTPResponse {
        HTTPResponse(status: status)
    }

    func serialized() -> Data {
        var headers = self.headers
        // RFC 7230: no Content-Length on a 204.
        if status != 204 {
            headers["Content-Length"] = String(body.count)
        }
        headers["Connection"] = "close"
        // Nothing this server returns may be cached or embedded by another page.
        headers["Cache-Control"] = "no-store"
        headers["X-Content-Type-Options"] = "nosniff"

        var head = "HTTP/1.1 \(status) \(HTTPResponse.reason(for: status))\r\n"
        for key in headers.keys.sorted() {
            head += "\(key): \(headers[key]!)\r\n"
        }
        head += "\r\n"

        var data = Data(head.utf8)
        data.append(body)
        return data
    }

    private static func reason(for status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 201: return "Created"
        case 204: return "No Content"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 409: return "Conflict"
        case 413: return "Payload Too Large"
        case 421: return "Misdirected Request"
        case 429: return "Too Many Requests"
        case 503: return "Service Unavailable"
        default: return "Status"
        }
    }
}

// MARK: - Parser

enum HTTPParseResult {
    case incomplete
    case request(HTTPRequest)
    case failure(HTTPResponse)
}

enum HTTPRequestParser {
    static func parse(_ buffer: Data) -> HTTPParseResult {
        let separator = Data("\r\n\r\n".utf8)
        guard let headerRange = buffer.range(of: separator) else { return .incomplete }

        let headerData = buffer.subdata(in: buffer.startIndex ..< headerRange.lowerBound)
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            return .failure(.error("bad_request", "Malformed request headers.", status: 400))
        }

        var lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            return .failure(.error("bad_request", "Missing request line.", status: 400))
        }
        lines.removeFirst()

        let parts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else {
            return .failure(.error("bad_request", "Malformed request line.", status: 400))
        }

        let method = String(parts[0]).uppercased()
        let target = String(parts[1])

        var headers: [String: String] = [:]
        for line in lines where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex ..< colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }

        if let encoding = headers["transfer-encoding"], !encoding.isEmpty {
            return .failure(.error("unsupported", "Chunked requests are not supported.", status: 400))
        }

        let contentLength = Int(headers["content-length"] ?? "0") ?? 0
        guard contentLength >= 0, contentLength <= PairingHTTPLimits.maximumBodySize else {
            return .failure(.error("payload_too_large", "Request body is too large.", status: 413))
        }

        let bodyStart = headerRange.upperBound
        let available = buffer.distance(from: bodyStart, to: buffer.endIndex)
        guard available >= contentLength else { return .incomplete }

        let body = buffer.subdata(in: bodyStart ..< buffer.index(bodyStart, offsetBy: contentLength))

        var path = target
        var query: [String: String] = [:]
        if let questionMark = target.firstIndex(of: "?") {
            path = String(target[target.startIndex ..< questionMark])
            let queryString = String(target[target.index(after: questionMark)...])
            for pair in queryString.split(separator: "&") {
                let keyValue = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let key = String(keyValue[0]).removingPercentEncoding ?? String(keyValue[0])
                let value = keyValue.count > 1 ? (String(keyValue[1]).removingPercentEncoding ?? String(keyValue[1])) : ""
                query[key] = value
            }
        }
        path = path.removingPercentEncoding ?? path

        return .request(HTTPRequest(method: method, path: path, query: query, headers: headers, body: body))
    }
}

