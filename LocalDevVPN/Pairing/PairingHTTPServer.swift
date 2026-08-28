//
//  PairingHTTPServer.swift
//  LocalDevVPN
//
//  A deliberately small HTTP/1.1 server bound to the loopback interface.
//

import Foundation
import Network

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
        guard contentLength >= 0, contentLength <= PairingHTTPServer.maximumBodySize else {
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

// MARK: - Server

/// Minimal loopback-only HTTP server.
///
/// Everything about it is intentionally small: one request per connection, no
/// keep-alive, hard caps on request size, and a bind that never leaves 127.0.0.1 so
/// nothing on the local network — or on the tunnel — can reach it.
final class PairingHTTPServer {
    /// Answers a request. The response block may be called later, off the network
    /// queue: parameters of a function type are escaping already.
    typealias Handler = (HTTPRequest, (HTTPResponse) -> Void) -> Void

    static let maximumBodySize = 64 * 1024
    static let maximumRequestSize = 96 * 1024
    private static let requestTimeout: TimeInterval = 15

    private let queue = DispatchQueue(label: "com.localdevvpn.pairing-bridge.server")
    private var listener: NWListener?
    private var handler: Handler?
    /// Connections in flight. `NWListener` does not retain them, so the server does.
    private var clients: [ObjectIdentifier: Client] = [:]

    private(set) var port: UInt16?

    var isRunning: Bool { listener != nil }

    /// Binds the first available port from `candidatePorts` so a web client can find
    /// the bridge by probing a short, documented list.
    func start(
        candidatePorts: [UInt16],
        handler: @escaping Handler,
        completion: @escaping (Result<UInt16, Error>) -> Void
    ) {
        queue.async {
            self.handler = handler
            self.attemptStart(ports: candidatePorts, completion: completion)
        }
    }

    func stop() {
        queue.async {
            self.listener?.stateUpdateHandler = nil
            self.listener?.cancel()
            self.listener = nil
            self.port = nil
            self.handler = nil
            for client in self.clients.values { client.close() }
            self.clients.removeAll()
        }
    }

    private func attemptStart(ports: [UInt16], completion: @escaping (Result<UInt16, Error>) -> Void) {
        guard let candidate = ports.first else {
            completion(.failure(PairingBridgeError.noAvailablePort))
            return
        }
        let remaining = Array(ports.dropFirst())

        guard let nwPort = NWEndpoint.Port(rawValue: candidate) else {
            attemptStart(ports: remaining, completion: completion)
            return
        }

        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: nwPort)
        if let tcp = parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
            tcp.noDelay = true
        }

        let listener: NWListener
        do {
            listener = try NWListener(using: parameters)
        } catch {
            attemptStart(ports: remaining, completion: completion)
            return
        }

        var settled = false
        listener.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                guard !settled else { return }
                settled = true
                let boundPort = listener.port?.rawValue ?? candidate
                self.listener = listener
                self.port = boundPort
                completion(.success(boundPort))
            case .failed, .waiting:
                guard !settled else { return }
                settled = true
                listener.stateUpdateHandler = nil
                listener.cancel()
                self.attemptStart(ports: remaining, completion: completion)
            case .cancelled:
                if self.listener === listener {
                    self.listener = nil
                    self.port = nil
                }
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }

        listener.start(queue: queue)
    }

    private func accept(_ connection: NWConnection) {
        guard PairingHTTPServer.isLoopback(connection.endpoint) else {
            // Unreachable while the listener is bound to 127.0.0.1, kept as a
            // second line of defence if that ever changes.
            connection.cancel()
            return
        }

        let client = Client(
            connection: connection,
            queue: queue,
            handler: { [weak self] request, respond in
                guard let handler = self?.handler else {
                    respond(.error("unavailable", "The pairing bridge is not running.", status: 503))
                    return
                }
                handler(request, respond)
            },
            onClose: { [weak self] client in
                self?.clients.removeValue(forKey: ObjectIdentifier(client))
            }
        )
        clients[ObjectIdentifier(client)] = client
        client.start()
    }

    static func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        switch host {
        case let .ipv4(address):
            return address.isLoopback || "\(address)".hasPrefix("127.")
        case let .ipv6(address):
            return address.isLoopback || "\(address)" == "::1"
        case let .name(name, _):
            return name == "localhost" || name == "127.0.0.1" || name == "::1"
        @unknown default:
            return false
        }
    }

    // MARK: - Connection

    private final class Client {
        private let connection: NWConnection
        private let queue: DispatchQueue
        private let handler: Handler
        private let onClose: (Client) -> Void
        private var buffer = Data()
        private var finished = false

        init(
            connection: NWConnection,
            queue: DispatchQueue,
            handler: @escaping Handler,
            onClose: @escaping (Client) -> Void
        ) {
            self.connection = connection
            self.queue = queue
            self.handler = handler
            self.onClose = onClose
        }

        func start() {
            connection.start(queue: queue)
            receive()
            queue.asyncAfter(deadline: .now() + PairingHTTPServer.requestTimeout) { [weak self] in
                guard let self = self, !self.finished else { return }
                self.finish()
            }
        }

        private func receive() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
                guard let self = self, !self.finished else { return }

                if let data = data, !data.isEmpty {
                    self.buffer.append(data)
                    if self.buffer.count > PairingHTTPServer.maximumRequestSize {
                        self.respond(.error("payload_too_large", "Request is too large.", status: 413))
                        return
                    }

                    switch HTTPRequestParser.parse(self.buffer) {
                    case .incomplete:
                        break
                    case let .request(request):
                        // Retain self until the handler answers.
                        self.handler(request) { response in
                            self.queue.async { self.respond(response) }
                        }
                        return
                    case let .failure(response):
                        self.respond(response)
                        return
                    }
                }

                if error != nil || isComplete {
                    self.finish()
                    return
                }

                self.receive()
            }
        }

        private func respond(_ response: HTTPResponse) {
            guard !finished else { return }
            finished = true
            connection.send(
                content: response.serialized(),
                completion: .contentProcessed { [weak self] _ in
                    guard let self = self else { return }
                    self.connection.cancel()
                    self.onClose(self)
                }
            )
        }

        private func finish() {
            guard !finished else { return }
            finished = true
            connection.cancel()
            onClose(self)
        }

        /// Tears the connection down without waiting for the in-flight request.
        func close() {
            finished = true
            connection.cancel()
        }
    }
}
