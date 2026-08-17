//
//  VPNShortcuts.swift
//  LocalDevVPN
//
//  Created by se2crid on 7/12/2025.
//

import Foundation

#if canImport(AppIntents)
import AppIntents

@available(iOS 16.0, *)
enum LocalDevVPNOperation: String, AppEnum {
    case enable
    case disable
    case toggle

    static var typeDisplayRepresentation = TypeDisplayRepresentation(name: "Operation")
    static var caseDisplayRepresentations: [LocalDevVPNOperation: DisplayRepresentation] = [
        .enable: "Enable",
        .disable: "Disable",
        .toggle: "Toggle",
    ]
}

@available(iOS 16.0, *)
enum IntermediateAddressPolicy: String, AppEnum {
    case appSetting
    case allow
    case disallow

    static var typeDisplayRepresentation = TypeDisplayRepresentation(name: "Intermediate Addresses")
    static var caseDisplayRepresentations: [IntermediateAddressPolicy: DisplayRepresentation] = [
        .appSetting: "Use App Setting",
        .allow: "Allow",
        .disallow: "Disallow",
    ]
}

@available(iOS 16.0, *)
struct ControlLocalDevVPNIntent: AppIntent {
    static var title: LocalizedStringResource = "LocalDevVPN"
    static var description = IntentDescription(
        "Enables, disables, or toggles LocalDevVPN. Optional IP addresses apply only to the new connection."
    )

    static var openAppWhenRun = false

    @Parameter(
        title: "Operation",
        description: "Choose whether to enable, disable, or toggle the VPN.",
        default: .enable
    )
    var operation: LocalDevVPNOperation

    @Parameter(
        title: "Tunnel IP",
        description: "A temporary tunnel interface address in CIDR notation. Leave empty to use the in-app setting."
    )
    var tunnelIP: String?

    @Parameter(
        title: "Device IP",
        description: "A temporary peer address in CIDR notation. Leave empty to use the in-app setting."
    )
    var deviceIP: String?

    @Parameter(
        title: "Intermediate Addresses",
        description: "Choose whether temporary IP validation uses the in-app setting, allows intermediate addresses, or disallows them.",
        default: .appSetting
    )
    var intermediateAddressPolicy: IntermediateAddressPolicy

    init() {}

    init(operation: LocalDevVPNOperation) {
        self.operation = operation
    }

    static var parameterSummary: some ParameterSummary {
        Summary("\(\.$operation) LocalDevVPN") {
            \.$tunnelIP
            \.$deviceIP
            \.$intermediateAddressPolicy
        }
    }

    @MainActor
    func perform() async throws -> some IntentResult {
        let tunnelManager = TunnelManager.shared
        let isActive = try await tunnelManager.isVPNActive()

        switch (operation, isActive) {
        case (.enable, false), (.toggle, false):
            tunnelManager.startVPN(temporaryAddresses: try temporaryAddresses(using: tunnelManager))
        case (.disable, true), (.toggle, true):
            tunnelManager.stopVPN()
        default:
            break
        }

        return .result()
    }

    @MainActor
    private func temporaryAddresses(using tunnelManager: TunnelManager) throws -> TunnelAddresses? {
        guard tunnelIP != nil || deviceIP != nil else { return nil }

        let configuredAddresses = tunnelManager.configuredAddresses
        let addresses = try CIDRValidator.shared.validatePair(
            tunnelIfaceInput: tunnelIP ?? configuredAddresses.interfaceIP,
            tunnelPeerInput: deviceIP ?? configuredAddresses.peerIP,
            allowIntermediateAddresses: allowsIntermediateAddresses
        )

        return TunnelAddresses(
            interfaceIP: addresses.iface.formattedCIDR,
            peerIP: addresses.peer.formattedCIDR
        )
    }

    private var allowsIntermediateAddresses: Bool {
        switch intermediateAddressPolicy {
        case .appSetting:
            return UserDefaults.standard.object(forKey: "allowIntermediateAddresses") as? Bool
                ?? TunnelConstants.defaultAllowIntermediateAddresses
        case .allow:
            return true
        case .disallow:
            return false
        }
    }
}

@available(iOS 16.0, *)
struct LocalDevVPNActions: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ControlLocalDevVPNIntent(operation: .enable),
            phrases: [
                "Start \(.applicationName)",
                "Connect to \(.applicationName)",
                "Enable \(.applicationName)"
            ],
            shortTitle: "Enable VPN",
            systemImageName: "lock.shield"
        )
        AppShortcut(
            intent: ControlLocalDevVPNIntent(operation: .disable),
            phrases: [
                "Stop \(.applicationName)",
                "Disconnect \(.applicationName)",
                "Disable \(.applicationName)"
            ],
            shortTitle: "Disable VPN",
            systemImageName: "lock.shield.slash"
        )
        AppShortcut(
            intent: ControlLocalDevVPNIntent(operation: .toggle),
            phrases: [
                "Toggle \(.applicationName)"
            ],
            shortTitle: "Toggle VPN",
            systemImageName: "arrow.triangle.2.circlepath"
        )
    }
}
#endif
