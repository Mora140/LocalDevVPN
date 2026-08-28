//
//  PairingBridgeViews.swift
//  LocalDevVPN
//
//  The two pieces of UI the pairing bridge needs: a settings section, and the
//  authorization prompt that gates every record hand-off.
//

import SwiftUI

#if os(iOS)
    import UniformTypeIdentifiers
#endif

/// New strings ship in `en.lproj` only; every other localization falls back to the
/// English text here instead of showing a raw key until it is translated.
private func bridgeText(_ key: String, _ fallback: String) -> String {
    NSLocalizedString(key, value: fallback, comment: "")
}

private let pairingTimeFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .short
    formatter.timeStyle = .short
    return formatter
}()

// MARK: - Settings

/// Lives inside `SettingsView`'s list.
struct PairingBridgeSection: View {
    @ObservedObject private var bridge = PairingBridge.shared
    @ObservedObject private var pairing = DevicePairingService.shared

    private var enabledBinding: Binding<Bool> {
        Binding(
            get: { bridge.isEnabled },
            set: { bridge.setEnabled($0) }
        )
    }

    var body: some View {
        Section(
            header: Text(bridgeText("pairing_bridge", "Pairing Bridge")),
            footer: Text(footer)
        ) {
            Toggle(bridgeText("pairing_bridge_allow", "Allow local web clients"), isOn: enabledBinding)

            if let address = bridge.baseURL {
                HStack {
                    Text(bridgeText("pairing_bridge_address", "Address"))
                    Spacer()
                    Text(address)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }

            if let error = bridge.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack {
                Text(bridgeText("pairing_record", "Pairing record"))
                Spacer()
                Text(recordStatus)
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }

            if let message = pairing.state.message, !message.isEmpty {
                Text(message)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            #if os(iOS)
                Button {
                    pairing.isRequestingFileImport = true
                } label: {
                    Label(
                        bridgeText("pairing_import_file", "Import Pairing File…"),
                        systemImage: "square.and.arrow.down"
                    )
                }
                .fileImporter(
                    isPresented: $pairing.isRequestingFileImport,
                    allowedContentTypes: [UTType.propertyList, UTType.data],
                    allowsMultipleSelection: false
                ) { result in
                    switch result {
                    case let .success(urls):
                        if let url = urls.first { pairing.completeImport(from: url) }
                    case let .failure(error):
                        pairing.fail(reason: error.localizedDescription)
                    }
                }
            #endif

            if pairing.hasRecord {
                Button {
                    pairing.clearRecord()
                } label: {
                    Label(
                        bridgeText("pairing_remove_record", "Remove Pairing Record"),
                        systemImage: "trash"
                    )
                    .foregroundColor(.red)
                }
            }

            if !bridge.authorizedClients.isEmpty {
                ForEach(bridge.authorizedClients) { client in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(client.origin)
                            .font(.footnote)
                        Text(deliveryDescription(for: client))
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }

                Button {
                    bridge.revokeAll()
                } label: {
                    Text(bridgeText("pairing_revoke_all", "Revoke All Access"))
                        .foregroundColor(.red)
                }
            }
        }
    }

    private var footer: String {
        let availability = pairing.systemFlowAvailability
        let base = bridgeText(
            "pairing_bridge_footer",
            "Lets a web page on this device ask LocalDevVPN for a pairing record over 127.0.0.1. "
                + "Nothing is shared until you approve the request, and the record never leaves the device."
        )
        return availability.isAvailable ? base : base + "\n\n" + availability.reason
    }

    private var recordStatus: String {
        guard let info = pairing.recordInfo else {
            return bridgeText("pairing_record_none", "None")
        }
        return info.fingerprint
    }

    private func deliveryDescription(for client: AuthorizedClientInfo) -> String {
        if let delivered = client.recordDeliveredAt {
            return String(
                format: bridgeText("pairing_record_shared_at", "Pairing record shared %@"),
                pairingTimeFormatter.string(from: delivered)
            )
        }
        return String(
            format: bridgeText("pairing_authorized_at", "Authorized %@"),
            pairingTimeFormatter.string(from: client.authorizedAt)
        )
    }
}

// MARK: - Authorization prompt

/// Shown over the whole app when a client asks for access.
///
/// This is an overlay rather than a sheet on purpose: it has to appear no matter
/// what else the app is presenting, and it is the one thing standing between a page
/// on this device and the pairing record.
struct PairingAuthorizationOverlay: View {
    @ObservedObject private var bridge = PairingBridge.shared

    var body: some View {
        if let request = bridge.pendingRequest {
            ZStack {
                Color.black.opacity(0.45)
                    .ignoresSafeArea()

                card(for: request)
                    .padding(.horizontal, 24)
            }
            .transition(.opacity)
        }
    }

    private func card(for request: PairingAuthorizationRequest) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .font(.largeTitle)
                .foregroundColor(.accentColor)

            Text(bridgeText("pairing_request_title", "Pairing request"))
                .font(.headline)

            VStack(spacing: 4) {
                Text(request.displayOrigin)
                    .font(.body.weight(.semibold))
                    .multilineTextAlignment(.center)
                if !request.isOriginVerified {
                    Text(bridgeText("pairing_origin_unverified", "Site name reported by the client — unverified"))
                        .font(.caption2)
                        .foregroundColor(.orange)
                        .multilineTextAlignment(.center)
                }
            }

            Text(String(
                format: bridgeText(
                    "pairing_request_body",
                    "%@ is asking LocalDevVPN for this device's pairing record. Only approve this if you started it."
                ),
                request.clientName
            ))
            .font(.footnote)
            .foregroundColor(.secondary)
            .multilineTextAlignment(.center)

            if let code = request.verificationCode {
                VStack(spacing: 4) {
                    Text(code)
                        .font(.system(.title, design: .monospaced))
                        .fontWeight(.bold)
                    Text(bridgeText("pairing_code_hint", "Approve only if the site shows this code."))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.vertical, 4)
            }

            HStack(spacing: 12) {
                Button {
                    bridge.denyPendingRequest()
                } label: {
                    Text(bridgeText("pairing_deny", "Deny"))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(PlainButtonStyle())
                .background(Color.gray.opacity(0.25))
                .cornerRadius(10)

                Button {
                    bridge.approvePendingRequest()
                } label: {
                    Text(bridgeText("pairing_approve", "Approve"))
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(PlainButtonStyle())
                .background(Color.accentColor)
                .cornerRadius(10)
            }
        }
        .padding(20)
        .frame(maxWidth: 420)
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(cardBackground)
        )
        .shadow(color: Color.black.opacity(0.3), radius: 20, x: 0, y: 10)
    }

    private var cardBackground: Color {
        #if os(tvOS)
            return Color.black.opacity(0.9)
        #else
            return Color(.secondarySystemBackground)
        #endif
    }
}
