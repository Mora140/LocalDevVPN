//
//  PairingHTTPServer.swift
//  LocalDevVPN
//
//  A deliberately small HTTP/1.1 server bound to the loopback interface.
//

import Foundation
import Network

// MARK: - Server

/// Minimal loopback-only HTTP server.
///
/// Everything about it is intentionally small: one request per connection, no
/// keep-alive, hard caps on request size, and a bind that never leaves 127.0.0.1 so
/// nothing on the local network — or on the tunnel — can reach it.
final class PairingHTTPServer {
    /// Answers a request. The response block escapes: handlers answer later, from
    /// another queue, once the user has had a chance to respond.
    typealias Handler = (HTTPRequest, @escaping (HTTPResponse) -> Void) -> Void

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
            // requiredLocalEndpoint should make this unreachable, but it has been
            // reported ignored on some platforms, and a bridge listening off
            // loopback would be a real problem. Check the peer as well.
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
                    if self.buffer.count > PairingHTTPLimits.maximumRequestSize {
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
