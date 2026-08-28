//
//  PairingBridge.swift
//  LocalDevVPN
//
//  Local-only HTTP bridge that lets a web signer ask LocalDevVPN to pair the
//  device and hand back the resulting pairing record.
//

import Combine
import Foundation
import Security
import UIKit

// MARK: - Errors

enum PairingBridgeError: LocalizedError {
    case noAvailablePort

    var errorDescription: String? {
        switch self {
        case .noAvailablePort:
            return "No loopback port in the LocalDevVPN range was free."
        }
    }
}

// MARK: - UI models

/// An authorization the user has to answer before a client gets anything.
struct PairingAuthorizationRequest: Identifiable, Equatable {
    let id: String
    let clientName: String
    /// Origin taken from the request's `Origin` header — the browser sets this and a
    /// page cannot forge it.
    let verifiedOrigin: String?
    /// Origin the client claimed in its request body. Never trusted, only shown when
    /// there is nothing better.
    let declaredOrigin: String?
    /// Shown by the requesting page so the user can confirm they are approving the
    /// tab in front of them. `nil` for deep-link requests, where the user arrived
    /// from the site by tapping a link.
    let verificationCode: String?
    /// Where an approved deep-link request will send the access token back to.
    let callbackURL: URL?
    let expiresAt: Date

    var isDeepLink: Bool { callbackURL != nil }

    var displayOrigin: String {
        if let origin = verifiedOrigin, !origin.isEmpty { return origin }
        if let callback = callbackURL, let host = callback.host {
            return "\(callback.scheme ?? "https")://\(host)"
        }
        if let declared = declaredOrigin, !declared.isEmpty { return declared }
        return "Unknown site"
    }

    var isOriginVerified: Bool {
        verifiedOrigin != nil || callbackURL != nil
    }
}

/// A client the user has authorized, for the transparency list in Settings.
struct AuthorizedClientInfo: Identifiable, Equatable {
    let id: String
    let clientName: String
    let origin: String
    let authorizedAt: Date
    let recordDeliveredAt: Date?
}

// MARK: - Bridge

/// The bridge itself: session bookkeeping, authorization and request routing.
///
/// Everything runs on the main queue. The HTTP server hands requests over with a
/// completion block, so no bridge state is ever touched from the network queue.
final class PairingBridge: ObservableObject {
    static let shared = PairingBridge()

    /// Bumped when the wire format changes.
    static let apiVersion = 1
    /// Ports a web client probes, in order, to find the bridge.
    static let candidatePorts: [UInt16] = [19842, 19843, 19844]
    /// Required on every request. Because it is not a CORS-safelisted header, a
    /// cross-origin caller is forced through a preflight, so no page can poke the
    /// bridge with a "simple" request it never gets to read the answer to.
    static let clientHeader = "X-LocalDevVPN-Client"

    private static let enabledDefaultsKey = "pairingBridgeEnabled"
    private static let authorizationTimeout: TimeInterval = 120
    private static let sessionLifetime: TimeInterval = 15 * 60
    private static let backgroundGracePeriod: TimeInterval = 25
    private static let maximumSessionsPerMinute = 5

    @Published private(set) var isEnabled: Bool
    @Published private(set) var port: UInt16?
    @Published private(set) var lastError: String?
    @Published private(set) var pendingRequest: PairingAuthorizationRequest?
    @Published private(set) var authorizedClients: [AuthorizedClientInfo] = []

    private let server = PairingHTTPServer()
    private let pairingService = DevicePairingService.shared
    private var sessions: [String: Session] = [:]
    private var sessionCreationTimestamps: [Date] = []
    private var expiryTimer: Timer?
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var lifecycleObservers: [NSObjectProtocol] = []

    var baseURL: String? {
        guard let port = port else { return nil }
        return "http://127.0.0.1:\(port)"
    }

    private init() {
        isEnabled = UserDefaults.standard.bool(forKey: PairingBridge.enabledDefaultsKey)

        lifecycleObservers = [
            NotificationCenter.default.addObserver(
                forName: UIApplication.didEnterBackgroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.applicationDidEnterBackground()
            },
            NotificationCenter.default.addObserver(
                forName: UIApplication.willEnterForegroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.applicationWillEnterForeground()
            },
        ]

        if isEnabled {
            startServer()
        }
    }

    // MARK: - Lifecycle

    func setEnabled(_ enabled: Bool) {
        guard enabled != isEnabled else { return }
        isEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: PairingBridge.enabledDefaultsKey)

        if enabled {
            startServer()
        } else {
            revokeAll()
            stopServer()
        }
    }

    private func startServer() {
        guard !server.isRunning else { return }
        lastError = nil
        server.start(candidatePorts: PairingBridge.candidatePorts) { [weak self] request, respond in
            DispatchQueue.main.async {
                guard let self = self else {
                    respond(.error("unavailable", "The pairing bridge is not running.", status: 503))
                    return
                }
                self.handle(request, respond: respond)
            }
        } completion: { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self else { return }
                switch result {
                case let .success(port):
                    self.port = port
                    self.startExpiryTimer()
                    VPNLogger.shared.log("Pairing bridge listening on 127.0.0.1:\(port)")
                case let .failure(error):
                    self.port = nil
                    self.lastError = error.localizedDescription
                    self.isEnabled = false
                    UserDefaults.standard.set(false, forKey: PairingBridge.enabledDefaultsKey)
                    VPNLogger.shared.log("Pairing bridge failed to start: \(error.localizedDescription)")
                }
            }
        }
    }

    private func stopServer() {
        server.stop()
        port = nil
        expiryTimer?.invalidate()
        expiryTimer = nil
        endBackgroundGrace()
        VPNLogger.shared.log("Pairing bridge stopped")
    }

    private func startExpiryTimer() {
        expiryTimer?.invalidate()
        let timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.expireStaleSessions()
        }
        expiryTimer = timer
    }

    private func applicationDidEnterBackground() {
        // Nobody can answer an authorization prompt while the app is in the
        // background, so a pending request is dropped rather than left open.
        if pendingRequest != nil {
            denyPendingRequest(reason: "LocalDevVPN was backgrounded")
        }

        guard isEnabled, server.isRunning else { return }

        // iOS suspends the app moments after it leaves the screen. Hold a short
        // assertion so a page that was just handed a token can still fetch the
        // record, then shut the listener down.
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "LocalDevVPN.PairingBridge") { [weak self] in
            self?.endBackgroundGrace()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + PairingBridge.backgroundGracePeriod) { [weak self] in
            self?.endBackgroundGrace()
        }
    }

    private func applicationWillEnterForeground() {
        guard isEnabled else { return }
        endBackgroundTaskOnly()
        startServer()
    }

    private func endBackgroundGrace() {
        guard backgroundTask != .invalid else { return }
        server.stop()
        port = nil
        endBackgroundTaskOnly()
    }

    private func endBackgroundTaskOnly() {
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }

    // MARK: - Authorization

    func approvePendingRequest() {
        guard let request = pendingRequest, var session = sessions[request.id] else { return }

        let token = PairingBridge.randomToken()
        session.state = .authorized
        session.accessToken = token
        session.authorizedAt = Date()
        session.lastSeenAt = Date()
        sessions[session.id] = session
        pendingRequest = nil
        refreshAuthorizedClients()

        VPNLogger.shared.log("Pairing bridge: authorized \(session.displayOrigin)")

        if let callback = session.callbackURL {
            openCallback(callback, session: session, token: token)
        }
    }

    func denyPendingRequest(reason: String = "Denied by the user") {
        guard let request = pendingRequest, var session = sessions[request.id] else {
            pendingRequest = nil
            return
        }
        session.state = .denied
        session.accessToken = nil
        sessions[session.id] = session
        pendingRequest = nil
        VPNLogger.shared.log("Pairing bridge: denied \(session.displayOrigin) (\(reason))")
    }

    func revokeAll() {
        guard !sessions.isEmpty || pendingRequest != nil else { return }
        sessions.removeAll()
        pendingRequest = nil
        refreshAuthorizedClients()
        VPNLogger.shared.log("Pairing bridge: all client authorizations revoked")
    }

    private func refreshAuthorizedClients() {
        authorizedClients = sessions.values
            .filter { $0.state == .authorized }
            .sorted { ($0.authorizedAt ?? $0.createdAt) > ($1.authorizedAt ?? $1.createdAt) }
            .map {
                AuthorizedClientInfo(
                    id: $0.id,
                    clientName: $0.clientName,
                    origin: $0.displayOrigin,
                    authorizedAt: $0.authorizedAt ?? $0.createdAt,
                    recordDeliveredAt: $0.recordDeliveredAt
                )
            }
    }

    private func expireStaleSessions() {
        let now = Date()
        var changed = false

        for (id, session) in sessions {
            switch session.state {
            case .pendingAuthorization:
                if now.timeIntervalSince(session.createdAt) > PairingBridge.authorizationTimeout {
                    sessions.removeValue(forKey: id)
                    if pendingRequest?.id == id { pendingRequest = nil }
                    changed = true
                }
            case .authorized:
                let start = session.authorizedAt ?? session.createdAt
                if now.timeIntervalSince(start) > PairingBridge.sessionLifetime {
                    sessions.removeValue(forKey: id)
                    changed = true
                }
            case .denied, .revoked:
                if now.timeIntervalSince(session.createdAt) > PairingBridge.sessionLifetime {
                    sessions.removeValue(forKey: id)
                    changed = true
                }
            }
        }

        if changed { refreshAuthorizedClients() }
    }

    // MARK: - Deep link entry point

    /// Handles `localdevvpn://pair`, the flow that works when the user is looking at
    /// the website: the site sends them here, they approve, and LocalDevVPN sends
    /// them back with an access token in the callback's fragment.
    func handleDeepLinkRequest(client: String?, callback: URL?, state: String?) {
        setEnabled(true)

        guard let callback = callback else {
            // No callback: the site polls over loopback instead, nothing to prepare.
            return
        }

        guard PairingBridge.isAcceptableCallback(callback) else {
            lastError = "That pairing link has an unsupported callback URL."
            VPNLogger.shared.log("Pairing bridge: rejected callback with scheme \(callback.scheme ?? "none")")
            return
        }

        let session = Session(
            id: PairingBridge.randomToken(),
            clientName: PairingBridge.sanitize(client) ?? "Web signer",
            verifiedOrigin: nil,
            declaredOrigin: nil,
            verificationCode: nil,
            callbackURL: callback,
            callbackState: PairingBridge.sanitize(state, limit: 128),
            createdAt: Date(),
            state: .pendingAuthorization,
            accessToken: nil,
            authorizedAt: nil,
            lastSeenAt: Date(),
            recordDeliveredAt: nil
        )
        sessions[session.id] = session
        pendingRequest = session.authorizationRequest(timeout: PairingBridge.authorizationTimeout)
    }

    private func openCallback(_ callback: URL, session: Session, token: String) {
        guard var components = URLComponents(url: callback, resolvingAgainstBaseURL: false) else { return }

        var fragment = "ldv_token=\(token)&ldv_session=\(session.id)"
        if let port = port { fragment += "&ldv_port=\(port)" }
        fragment += "&ldv_api=\(PairingBridge.apiVersion)"
        if let state = session.callbackState,
           let encoded = state.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            fragment += "&ldv_state=\(encoded)"
        }
        // The token travels in the fragment so it never reaches the site's server in
        // a request line, a referrer or an access log.
        components.fragment = fragment

        guard let url = components.url else { return }
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }

    static func isAcceptableCallback(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        if scheme == "https" { return true }
        if scheme == "http" {
            let host = url.host?.lowercased()
            return host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
        }
        return false
    }

    // MARK: - Request handling

    private func handle(_ request: HTTPRequest, respond: @escaping (HTTPResponse) -> Void) {
        let origin = request.header("origin")

        if request.method == "OPTIONS" {
            var preflight = withCORS(.empty(status: 204), origin: origin)
            // Chromium's Private Network Access check. WebKit does not implement it,
            // so this only matters for non-Safari clients; answering it does not
            // loosen anything, because access still hangs on the user approving the
            // request in the app.
            if request.header("access-control-request-private-network")?.lowercased() == "true" {
                preflight.headers["Access-Control-Allow-Private-Network"] = "true"
            }
            respond(preflight)
            return
        }

        // A page that reaches the bridge through a hostname resolving to 127.0.0.1
        // (DNS rebinding) sends that hostname in Host; only the literal loopback
        // authority is accepted.
        guard isAcceptableHost(request.header("host")) else {
            respond(withCORS(.error("invalid_host", "Use http://127.0.0.1 to reach the bridge.", status: 421), origin: origin))
            return
        }

        let clientHeader = request.header(PairingBridge.clientHeader) ?? ""
        guard !clientHeader.isEmpty else {
            respond(withCORS(.error(
                "missing_client_header",
                "Send \(PairingBridge.clientHeader) with every request.",
                status: 400
            ), origin: origin))
            return
        }

        expireStaleSessions()
        respond(withCORS(route(request, origin: origin), origin: origin))
    }

    private func route(_ request: HTTPRequest, origin: String?) -> HTTPResponse {
        switch (request.method, request.path) {
        case ("GET", "/v1/status"):
            return statusResponse()

        case ("POST", "/v1/sessions"):
            return createSession(request, origin: origin)

        case ("GET", "/v1/pairing-record"):
            return pairingRecordResponse(request)

        case ("POST", "/v1/tunnel"):
            return tunnelResponse(request)

        default:
            break
        }

        let prefix = "/v1/sessions/"
        guard request.path.hasPrefix(prefix) else {
            return .error("not_found", "Unknown endpoint.", status: 404)
        }

        var identifier = String(request.path.dropFirst(prefix.count))
        var wantsPairing = false
        if identifier.hasSuffix("/pairing") {
            identifier = String(identifier.dropLast("/pairing".count))
            wantsPairing = true
        }

        guard !identifier.isEmpty, let session = sessions[identifier] else {
            return .error("unknown_session", "That session does not exist or has expired.", status: 404)
        }

        if wantsPairing {
            guard request.method == "POST" else {
                return .error("method_not_allowed", "Use POST.", status: 405)
            }
            guard authorizedSession(for: request)?.id == session.id else {
                return unauthorizedResponse()
            }
            pairingService.begin(requestedBy: session.clientName)
            return .json(sessionBody(sessions[session.id] ?? session), status: 202)
        }

        switch request.method {
        case "GET":
            touch(session.id)
            return .json(sessionBody(sessions[session.id] ?? session))
        case "DELETE":
            sessions.removeValue(forKey: session.id)
            if pendingRequest?.id == session.id { pendingRequest = nil }
            refreshAuthorizedClients()
            return .empty(status: 204)
        default:
            return .error("method_not_allowed", "Use GET or DELETE.", status: 405)
        }
    }

    // MARK: - Endpoints

    private func statusResponse() -> HTTPResponse {
        let availability = pairingService.systemFlowAvailability
        let addresses = TunnelManager.shared.configuredAddresses

        return .json([
            "api": PairingBridge.apiVersion,
            "app": "LocalDevVPN",
            "version": Bundle.main.shortVersion,
            "authorization_required": true,
            "client_header": PairingBridge.clientHeader,
            "tunnel": [
                "status": PairingBridge.describe(TunnelManager.shared.tunnelStatus),
                "interface_ip": addresses.interfaceIP,
                "device_ip": addresses.peerIP,
            ],
            "pairing": [
                "system_flow_available": availability.isAvailable,
                "mechanism": availability.mechanism,
                "reason": availability.reason,
            ],
            // Whether a record exists, never the record or its fingerprint: those
            // need an authorized session.
            "record": ["available": pairingService.hasRecord],
        ])
    }

    private func createSession(_ request: HTTPRequest, origin: String?) -> HTTPResponse {
        let now = Date()
        sessionCreationTimestamps = sessionCreationTimestamps.filter { now.timeIntervalSince($0) < 60 }
        guard sessionCreationTimestamps.count < PairingBridge.maximumSessionsPerMinute else {
            return .error("rate_limited", "Too many authorization requests. Try again in a minute.", status: 429)
        }

        if pendingRequest != nil {
            return .error(
                "authorization_pending",
                "LocalDevVPN is already asking the user about another request.",
                status: 409
            )
        }

        let body = request.jsonBody ?? [:]
        let clientName = PairingBridge.sanitize(body["client"] as? String) ?? "Web signer"
        let declaredOrigin = PairingBridge.sanitize(body["origin"] as? String, limit: 128)

        sessionCreationTimestamps.append(now)

        let session = Session(
            id: PairingBridge.randomToken(),
            clientName: clientName,
            verifiedOrigin: PairingBridge.sanitize(origin, limit: 128),
            declaredOrigin: declaredOrigin,
            verificationCode: PairingBridge.randomCode(),
            callbackURL: nil,
            callbackState: nil,
            createdAt: now,
            state: .pendingAuthorization,
            accessToken: nil,
            authorizedAt: nil,
            lastSeenAt: now,
            recordDeliveredAt: nil
        )
        sessions[session.id] = session
        pendingRequest = session.authorizationRequest(timeout: PairingBridge.authorizationTimeout)

        VPNLogger.shared.log("Pairing bridge: authorization requested by \(session.displayOrigin)")

        var response = sessionBody(session)
        if let code = session.verificationCode { response["verification_code"] = code }
        response["poll_after_ms"] = 1000
        return .json(response, status: 201)
    }

    private func pairingRecordResponse(_ request: HTTPRequest) -> HTTPResponse {
        guard var session = authorizedSession(for: request) else { return unauthorizedResponse() }

        guard let data = pairingService.authorizedRecordData(),
              let info = pairingService.recordInfo
        else {
            return .error(
                "no_pairing_record",
                "No pairing record is available yet. Start pairing first.",
                status: 409
            )
        }

        session.lastSeenAt = Date()
        session.recordDeliveredAt = Date()
        sessions[session.id] = session
        refreshAuthorizedClients()
        VPNLogger.shared.log("Pairing bridge: pairing record \(info.fingerprint) delivered to \(session.displayOrigin)")

        let accept = request.header("accept")?.lowercased() ?? ""
        if accept.contains("application/x-plist") || accept.contains("application/octet-stream") {
            return .binary(data, contentType: "application/x-plist")
        }

        return .json([
            "format": "plist",
            "encoding": "base64",
            "data": data.base64EncodedString(),
            "fingerprint": info.fingerprint,
            "host_id": info.hostID,
        ])
    }

    private func tunnelResponse(_ request: HTTPRequest) -> HTTPResponse {
        guard authorizedSession(for: request) != nil else { return unauthorizedResponse() }

        let action = (request.jsonBody?["action"] as? String)?.lowercased() ?? "status"
        let manager = TunnelManager.shared

        switch action {
        case "start":
            manager.startVPN()
        case "stop":
            manager.stopVPN()
        case "status":
            break
        default:
            return .error("bad_request", "Unknown action.", status: 400)
        }

        let addresses = manager.configuredAddresses
        return .json([
            "status": PairingBridge.describe(manager.tunnelStatus),
            "interface_ip": addresses.interfaceIP,
            "device_ip": addresses.peerIP,
        ])
    }

    // MARK: - Helpers

    private func sessionBody(_ session: Session) -> [String: Any] {
        var body: [String: Any] = [
            "session_id": session.id,
            "state": session.state.rawValue,
            "client": session.clientName,
        ]

        switch session.state {
        case .pendingAuthorization:
            let remaining = PairingBridge.authorizationTimeout - Date().timeIntervalSince(session.createdAt)
            body["expires_in"] = max(0, Int(remaining))
        case .authorized:
            let start = session.authorizedAt ?? session.createdAt
            let remaining = PairingBridge.sessionLifetime - Date().timeIntervalSince(start)
            body["expires_in"] = max(0, Int(remaining))
            if let token = session.accessToken { body["access_token"] = token }

            let state = pairingService.state
            var pairing: [String: Any] = ["state": state.apiState]
            if let message = state.message { pairing["message"] = message }
            if let code = state.code { pairing["code"] = code }
            body["pairing"] = pairing

            var record: [String: Any] = ["available": pairingService.hasRecord]
            if let info = pairingService.recordInfo {
                record["fingerprint"] = info.fingerprint
            }
            body["record"] = record
        case .denied, .revoked:
            body["expires_in"] = 0
        }

        return body
    }

    private func authorizedSession(for request: HTTPRequest) -> Session? {
        guard let header = request.header("authorization") else { return nil }
        let parts = header.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, parts[0].lowercased() == "bearer" else { return nil }

        let token = String(parts[1]).trimmingCharacters(in: .whitespaces)
        guard !token.isEmpty else { return nil }

        for session in sessions.values where session.state == .authorized {
            guard let stored = session.accessToken else { continue }
            if PairingBridge.constantTimeEquals(stored, token) { return session }
        }
        return nil
    }

    private func unauthorizedResponse() -> HTTPResponse {
        var response = HTTPResponse.error(
            "unauthorized",
            "This request needs an access token from a session the user approved in LocalDevVPN.",
            status: 401
        )
        response.headers["WWW-Authenticate"] = "Bearer realm=\"LocalDevVPN\""
        return response
    }

    private func touch(_ sessionID: String) {
        guard var session = sessions[sessionID] else { return }
        session.lastSeenAt = Date()
        sessions[sessionID] = session
    }

    private func isAcceptableHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased() else { return false }

        let authority: String
        if host.hasPrefix("["), let closing = host.firstIndex(of: "]") {
            authority = String(host[host.startIndex ... closing])
        } else {
            authority = host.split(separator: ":").first.map(String.init) ?? host
        }

        return authority == "127.0.0.1" || authority == "localhost" || authority == "[::1]"
    }

    private func withCORS(_ response: HTTPResponse, origin: String?) -> HTTPResponse {
        var response = response
        // Any origin may *ask*; nothing is handed over without the user approving it
        // in the app, and credentials are never allowed, so the browser never
        // attaches ambient cookies to these requests.
        response.headers["Access-Control-Allow-Origin"] = origin ?? "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, \(PairingBridge.clientHeader)"
        response.headers["Access-Control-Max-Age"] = "600"
        response.headers["Vary"] = "Origin"
        return response
    }

    private static func describe(_ status: TunnelManager.TunnelStatus) -> String {
        switch status {
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .disconnecting: return "disconnecting"
        case .error: return "error"
        }
    }

    private static func sanitize(_ value: String?, limit: Int = 64) -> String? {
        guard let value = value else { return nil }
        let stripped = value.components(separatedBy: .controlCharacters).joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !stripped.isEmpty else { return nil }
        return String(stripped.prefix(limit))
    }

    private static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        if SecRandomCopyBytes(kSecRandomDefault, count, &bytes) != errSecSuccess {
            for index in 0 ..< count { bytes[index] = UInt8.random(in: 0 ... 255) }
        }
        return Data(bytes)
    }

    /// 256 bits, base64url, used for both session ids and access tokens.
    static func randomToken() -> String {
        randomBytes(32)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func randomCode() -> String {
        let bytes = randomBytes(4)
        let value = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } % 1_000_000
        return String(format: "%06u", value)
    }

    private static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in 0 ..< left.count {
            difference |= left[index] ^ right[index]
        }
        return difference == 0
    }

    // MARK: - Session

    private struct Session {
        enum State: String {
            case pendingAuthorization = "pending_authorization"
            case authorized
            case denied
            case revoked
        }

        let id: String
        let clientName: String
        let verifiedOrigin: String?
        let declaredOrigin: String?
        let verificationCode: String?
        let callbackURL: URL?
        let callbackState: String?
        let createdAt: Date
        var state: State
        var accessToken: String?
        var authorizedAt: Date?
        var lastSeenAt: Date
        var recordDeliveredAt: Date?

        var displayOrigin: String {
            authorizationRequest(timeout: 0).displayOrigin
        }

        func authorizationRequest(timeout: TimeInterval) -> PairingAuthorizationRequest {
            PairingAuthorizationRequest(
                id: id,
                clientName: clientName,
                verifiedOrigin: verifiedOrigin,
                declaredOrigin: declaredOrigin,
                verificationCode: verificationCode,
                callbackURL: callbackURL,
                expiresAt: createdAt.addingTimeInterval(timeout)
            )
        }
    }
}
