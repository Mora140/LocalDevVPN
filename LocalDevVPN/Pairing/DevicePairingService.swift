//
//  DevicePairingService.swift
//  LocalDevVPN
//
//  Drives the device pairing flow that produces a pairing record.
//

import Combine
import Foundation
import UIKit

// MARK: - Flow State

/// State of a pairing attempt. The web client sees `apiState` and `message`.
enum PairingFlowState: Equatable {
    /// Nothing in flight.
    case idle
    /// The pairing flow cannot run on this OS build; `reason` explains why.
    case unavailable(reason: String)
    /// Waiting for the person holding the device. `code` carries a PIN when the
    /// system flow shows one, `instruction` is what the user has to do.
    case awaitingUserAction(instruction: String, code: String?)
    /// The system flow is running and needs no user input right now.
    case inProgress
    case completed(fingerprint: String)
    case failed(reason: String)

    var apiState: String {
        switch self {
        case .idle: return "idle"
        case .unavailable: return "unavailable"
        case .awaitingUserAction: return "awaiting_user_action"
        case .inProgress: return "in_progress"
        case .completed: return "completed"
        case .failed: return "failed"
        }
    }

    var message: String? {
        switch self {
        case .idle, .inProgress:
            return nil
        case let .unavailable(reason):
            return reason
        case let .awaitingUserAction(instruction, _):
            return instruction
        case .completed:
            return nil
        case let .failed(reason):
            return reason
        }
    }

    var code: String? {
        if case let .awaitingUserAction(_, code) = self { return code }
        return nil
    }
}

// MARK: - Flow Provider

/// Whether a pairing mechanism can run, and which one it is.
struct PairingFlowAvailability {
    let isAvailable: Bool
    /// The OS mechanism this provider drives, for diagnostics.
    let mechanism: String
    /// Why it is (not) usable. Shown in the UI and returned by `GET /v1/status`.
    let reason: String
}

enum PairingFlowError: LocalizedError {
    case unavailable(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case let .unavailable(reason): return reason
        case .cancelled: return "Pairing was cancelled."
        }
    }
}

/// A source of pairing records.
///
/// The bridge does not care where a record comes from, which keeps the system flow
/// and the manual import path interchangeable: both report progress through
/// `PairingFlowState` and finish with a `PairingRecord`.
protocol PairingFlowProvider: AnyObject {
    var availability: PairingFlowAvailability { get }
    func start(
        update: @escaping (PairingFlowState) -> Void,
        completion: @escaping (Result<PairingRecord, Error>) -> Void
    )
    func cancel()
}

// MARK: - System Pairing Flow

/// Apple's on-device / remote pairing flow.
///
/// iOS has two pairing mechanisms that mint a lockdown pairing record, and neither
/// is reachable from a sandboxed third-party app (see `docs/pairing-bridge.md`):
///
/// * iOS 16 and earlier: `lockdownd`'s `Pair` request, which a *host* sends over USB
///   or over the network and which raises the "Trust This Computer?" prompt. It is
///   gated on `com.apple.mobile.lockdown` access that apps do not get, so an app
///   cannot pair the device it runs on.
/// * iOS 17 and later: RemoteXPC "remote pairing" — the six-digit PIN Xcode shows
///   when you pair a device wirelessly. It is served by `remotepairingd` behind
///   `com.apple.internal.dt.remote.pairing`, an Apple-internal entitlement that is
///   not issued to third-party apps and would fail App Review.
///
/// The provider therefore reports its availability honestly instead of shipping a
/// private-API path. A fork that carries the required entitlements can compile in a
/// real implementation behind `LOCALDEVVPN_NATIVE_PAIRING` without touching the
/// bridge, the API surface, or the UI.
final class SystemPairingFlowProvider: PairingFlowProvider {
    var availability: PairingFlowAvailability {
        #if LOCALDEVVPN_NATIVE_PAIRING
            return NativePairingFlow.availability
        #else
            if #available(iOS 17.0, tvOS 17.0, *) {
                return PairingFlowAvailability(
                    isAvailable: false,
                    mechanism: "remote-pairing (RemoteXPC)",
                    reason: "iOS 17+ mints pairing records through remotepairingd, which requires the "
                        + "com.apple.internal.dt.remote.pairing entitlement. Apple does not issue it to "
                        + "third-party apps, so LocalDevVPN cannot start the PIN flow itself. Import a "
                        + "pairing file instead."
                )
            } else {
                return PairingFlowAvailability(
                    isAvailable: false,
                    mechanism: "lockdown pairing (host trust)",
                    reason: "On this iOS version a pairing record is created by a trusted host that sends "
                        + "lockdownd a Pair request and raises the Trust This Computer prompt. Apps cannot "
                        + "reach lockdownd on the device they run on. Import a pairing file instead."
                )
            }
        #endif
    }

    func start(
        update: @escaping (PairingFlowState) -> Void,
        completion: @escaping (Result<PairingRecord, Error>) -> Void
    ) {
        #if LOCALDEVVPN_NATIVE_PAIRING
            NativePairingFlow.start(update: update, completion: completion)
        #else
            let reason = availability.reason
            update(.unavailable(reason: reason))
            completion(.failure(PairingFlowError.unavailable(reason)))
        #endif
    }

    func cancel() {
        #if LOCALDEVVPN_NATIVE_PAIRING
            NativePairingFlow.cancel()
        #endif
    }
}

// MARK: - Pairing Service

/// Owns the pairing record and the pairing flow.
///
/// All mutation happens on the main queue; the bridge is a main-queue actor too, so
/// state stays consistent without extra locking.
final class DevicePairingService: ObservableObject {
    static let shared = DevicePairingService()

    @Published private(set) var state: PairingFlowState = .idle
    @Published private(set) var recordInfo: StoredRecordInfo?
    /// Set when the flow needs the user to pick a pairing file; the settings UI
    /// observes this and raises the document picker.
    @Published var isRequestingFileImport = false

    private let store = PairingRecordStore.shared
    private let systemProvider = SystemPairingFlowProvider()

    private init() {
        recordInfo = store.info()
    }

    var systemFlowAvailability: PairingFlowAvailability {
        systemProvider.availability
    }

    var hasRecord: Bool {
        recordInfo != nil
    }

    /// Raw record bytes. Only the bridge calls this, and only for a session the user
    /// authorized.
    func authorizedRecordData() -> Data? {
        store.load()?.data
    }

    /// Starts Apple's pairing flow when the OS exposes one, and otherwise falls back
    /// to a user-driven import, which is the only App Store-safe way to get a record
    /// onto the device today.
    func begin(requestedBy client: String?) {
        let availability = systemProvider.availability
        VPNLogger.shared.log("Pairing bridge: pairing requested by \(client ?? "an unnamed client")")

        guard availability.isAvailable else {
            VPNLogger.shared.log("Pairing bridge: system pairing flow unavailable (\(availability.mechanism))")
            requestFileImport(reason: availability.reason)
            return
        }

        state = .inProgress
        systemProvider.start(
            update: { [weak self] newState in
                DispatchQueue.main.async { self?.state = newState }
            },
            completion: { [weak self] result in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    switch result {
                    case let .success(record):
                        self.storeRecord(record, source: "system pairing flow")
                    case let .failure(error):
                        self.requestFileImport(reason: error.localizedDescription)
                    }
                }
            }
        )
    }

    /// Puts the flow into "waiting for the user to hand us a pairing file" and asks
    /// the UI to raise the document picker.
    func requestFileImport(reason: String?) {
        var instruction = "Import a pairing file to finish pairing."
        if let reason = reason, !reason.isEmpty {
            instruction = reason
        }
        state = .awaitingUserAction(instruction: instruction, code: nil)
        #if os(iOS)
            // Only raise the picker if someone is looking at the app; otherwise the
            // state message tells them what to do when they come back.
            if UIApplication.shared.applicationState == .active {
                isRequestingFileImport = true
            }
        #endif
    }

    func completeImport(from url: URL) {
        let needsScope = url.startAccessingSecurityScopedResource()
        defer { if needsScope { url.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: url)
            let record = try PairingRecord(plistData: data)
            storeRecord(record, source: "imported pairing file")
        } catch let error as PairingRecordError {
            fail(reason: error.localizedDescription)
        } catch {
            fail(reason: PairingRecordError.fileUnreadable.localizedDescription)
        }
    }

    func fail(reason: String) {
        state = .failed(reason: reason)
        VPNLogger.shared.log("Pairing bridge: pairing failed – \(reason)")
    }

    func cancel() {
        systemProvider.cancel()
        isRequestingFileImport = false
        state = hasRecord ? .idle : .failed(reason: PairingFlowError.cancelled.localizedDescription)
    }

    func clearRecord() {
        store.clear()
        recordInfo = nil
        state = .idle
        VPNLogger.shared.log("Pairing bridge: pairing record removed")
    }

    private func storeRecord(_ record: PairingRecord, source: String) {
        do {
            try store.save(record)
            recordInfo = store.info()
            state = .completed(fingerprint: record.fingerprint)
            isRequestingFileImport = false
            VPNLogger.shared.log("Pairing bridge: stored pairing record \(record.fingerprint) (\(source))")
        } catch {
            fail(reason: "The pairing record could not be saved: \(error.localizedDescription)")
        }
    }
}
