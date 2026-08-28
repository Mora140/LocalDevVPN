//
//  PairingRecord.swift
//  LocalDevVPN
//
//  Device pairing record ("pairing file") handling for the local pairing bridge.
//

import CryptoKit
import Foundation

// MARK: - Errors

enum PairingRecordError: LocalizedError {
    case empty
    case tooLarge
    case notAPropertyList
    case missingKeys([String])
    case malformed
    case fileUnreadable

    var errorDescription: String? {
        switch self {
        case .empty:
            return "The pairing file is empty."
        case .tooLarge:
            return "The pairing file is larger than \(PairingRecord.maximumSize / 1024) KB."
        case .notAPropertyList:
            return "The pairing file is not a property list."
        case let .missingKeys(keys):
            return "The pairing file is missing required keys: \(keys.joined(separator: ", "))."
        case .malformed:
            return "The pairing file is missing a usable HostID / SystemBUID."
        case .fileUnreadable:
            return "The pairing file could not be read."
        }
    }
}

// MARK: - Pairing Record

/// A lockdown pairing record for the device this app runs on.
///
/// The raw bytes stay on the device: they are written only to the app container
/// (with data protection enabled) and handed out only over the loopback bridge,
/// and only to a session the user explicitly authorized.
struct PairingRecord {
    /// Keys that every usable lockdown pairing record contains.
    static let requiredKeys = [
        "DeviceCertificate",
        "HostCertificate",
        "HostPrivateKey",
        "HostID",
        "SystemBUID",
    ]

    /// Real pairing records are a few KB; anything bigger is rejected outright.
    static let maximumSize = 128 * 1024

    /// Raw property list bytes. Never logged.
    let data: Data
    let hostID: String
    let systemBUID: String
    let udid: String?

    /// Truncated SHA-256 of the record, safe to show in the UI and in logs so the
    /// user can tell two records apart without exposing key material.
    let fingerprint: String

    init(plistData: Data) throws {
        guard !plistData.isEmpty else { throw PairingRecordError.empty }
        guard plistData.count <= PairingRecord.maximumSize else { throw PairingRecordError.tooLarge }

        let object: Any
        do {
            object = try PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)
        } catch {
            throw PairingRecordError.notAPropertyList
        }

        guard let plist = object as? [String: Any] else { throw PairingRecordError.notAPropertyList }

        let missing = PairingRecord.requiredKeys.filter { plist[$0] == nil }
        guard missing.isEmpty else { throw PairingRecordError.missingKeys(missing) }

        guard
            let hostID = plist["HostID"] as? String, !hostID.isEmpty,
            let systemBUID = plist["SystemBUID"] as? String, !systemBUID.isEmpty
        else {
            throw PairingRecordError.malformed
        }

        self.data = plistData
        self.hostID = hostID
        self.systemBUID = systemBUID
        udid = plist["UDID"] as? String
        fingerprint = PairingRecord.fingerprint(of: plistData)
    }

    static func fingerprint(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }
}

// MARK: - Stored Record Info

/// Everything the UI and the bridge may know about a stored record without
/// touching the record itself.
struct StoredRecordInfo: Equatable {
    let fingerprint: String
    let storedAt: Date
    let hostID: String
}

// MARK: - Store

/// On-device storage for the pairing record.
///
/// The record lives in the app's Application Support directory with complete data
/// protection and is excluded from backups, so it is never copied off the device by
/// iCloud or by an encrypted local backup.
final class PairingRecordStore {
    static let shared = PairingRecordStore()

    private let directoryName = "PairingBridge"
    private let fileName = "pairing-record.plist"
    private var cached: PairingRecord?

    private init() {}

    private var directoryURL: URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base.appendingPathComponent(directoryName, isDirectory: true)
    }

    private var fileURL: URL? {
        directoryURL?.appendingPathComponent(fileName, isDirectory: false)
    }

    /// Loads (and caches) the stored record, if there is one.
    func load() -> PairingRecord? {
        if let cached = cached { return cached }
        guard let url = fileURL, FileManager.default.fileExists(atPath: url.path) else { return nil }

        do {
            let data = try Data(contentsOf: url)
            let record = try PairingRecord(plistData: data)
            cached = record
            return record
        } catch {
            VPNLogger.shared.log("Pairing bridge: stored pairing record is unusable, discarding it")
            clear()
            return nil
        }
    }

    func info() -> StoredRecordInfo? {
        guard let record = load(), let url = fileURL else { return nil }
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let storedAt = (attributes?[.modificationDate] as? Date) ?? Date()
        return StoredRecordInfo(fingerprint: record.fingerprint, storedAt: storedAt, hostID: record.hostID)
    }

    func save(_ record: PairingRecord) throws {
        guard let directory = directoryURL, let url = fileURL else { throw PairingRecordError.fileUnreadable }

        var attributes: [FileAttributeKey: Any] = [:]
        #if os(iOS)
            attributes[.protectionKey] = FileProtectionType.complete
        #endif

        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: attributes
        )

        #if os(iOS)
            try record.data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
            try record.data.write(to: url, options: [.atomic])
        #endif

        var excluded = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? excluded.setResourceValues(values)

        cached = record
    }

    func clear() {
        cached = nil
        guard let url = fileURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
