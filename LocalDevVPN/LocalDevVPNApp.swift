//
//  LocalDevVPNApp.swift
//  LocalDevVPN
//
//  Created by Stossy11 on 28/03/2025.
//

import SwiftUI

@main
struct LocalDevVPNApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onOpenURL { url in
                    handleURL(url)
                }
        }
    }
    
    private func handleURL(_ url: URL) {
        guard url.scheme == "localdevvpn" else { return }
        
        let tunnelManager = TunnelManager.shared
        
        switch url.host {
        case "enable":
            tunnelManager.startVPN()
            if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
               let schemeParam = components.queryItems?.first(where: { $0.name == "scheme" })?.value {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    let callbackURL = URL(string: "\(schemeParam)://")!
                    UIApplication.shared.open(callbackURL)
                }
            }
        case "disable":
            tunnelManager.stopVPN()
            if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
               let schemeParam = components.queryItems?.first(where: { $0.name == "scheme" })?.value {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    let callbackURL = URL(string: "\(schemeParam)://")!
                    UIApplication.shared.open(callbackURL)
                }
            }
        case "pair":
            handlePairingRequest(url)
        default:
            break
        }
    }

    /// `localdevvpn://pair?client=…&callback=https://…&state=…`
    ///
    /// The web-facing half of the pairing bridge. A page in Safari cannot reach a
    /// suspended app, so the site sends the user here instead: LocalDevVPN comes to
    /// the front, asks for authorization, and — once the user approves — hands the
    /// access token back through the callback's fragment.
    private func handlePairingRequest(_ url: URL) {
        let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        let callback = queryItems?
            .first(where: { $0.name == "callback" })?
            .value
            .flatMap { URL(string: $0) }

        PairingBridge.shared.handleDeepLinkRequest(
            client: queryItems?.first(where: { $0.name == "client" })?.value,
            callback: callback,
            state: queryItems?.first(where: { $0.name == "state" })?.value
        )
    }
}
