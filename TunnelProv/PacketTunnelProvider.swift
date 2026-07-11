//
//  PacketTunnelProvider.swift
//  TunnelProv
//
//  Created by Stossy11 on 28/03/2025.
//

import NetworkExtension
#if DEBUG
import os.log
#endif

@inline(__always)
private func tunnelLog(_ message: @autoclosure () -> String) {
#if DEBUG
    os_log("[TunnelProv] %{public}@", type: .error, message())
#endif
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    var tunnelDeviceIp: String = TunnelConstants.defaultDeviceIP
    var tunnelFakeIp: String = TunnelConstants.defaultFakeIP
    var tunnelSubnetMask: String = TunnelConstants.defaultSubnetMask
    
    private var deviceIpValue: UInt32 = 0
    private var fakeIpValue: UInt32 = 0
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        if let options = options {
            for (key, val) in options {
                tunnelLog("startTunnel option \(key) = \(String(describing: val))")
            }
        } else {
            tunnelLog("startTunnel: options is nil")
        }
        
        if let deviceIp = options?["TunnelDeviceIP"] as? String {
            tunnelLog("Option TunnelDeviceIP overridden to: \(deviceIp)")
            tunnelDeviceIp = deviceIp
        }
        if let fakeIp = options?["TunnelFakeIP"] as? String {
            tunnelLog("Option TunnelFakeIP overridden to: \(fakeIp)")
            tunnelFakeIp = fakeIp
        }
        if let subnetMask = options?["TunnelSubnetMask"] as? String {
            tunnelLog("Option TunnelSubnetMask overridden to: \(subnetMask)")
            tunnelSubnetMask = subnetMask
        }
        
        deviceIpValue = ipToUInt32(tunnelDeviceIp)
        fakeIpValue = ipToUInt32(tunnelFakeIp)
        
        tunnelLog("Configuring P2P settings: remoteAddress=\(tunnelFakeIp), localAddress=\(tunnelDeviceIp), subnetMask=\(tunnelSubnetMask)")
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelFakeIp)
        let ipv4 = NEIPv4Settings(addresses: [tunnelDeviceIp], subnetMasks: [tunnelSubnetMask])
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: tunnelDeviceIp, subnetMask: tunnelSubnetMask),
            NEIPv4Route(destinationAddress: tunnelFakeIp, subnetMask: tunnelSubnetMask)
        ]
        ipv4.excludedRoutes = [.default()]
        settings.ipv4Settings = ipv4
        
        tunnelLog("Calling setTunnelNetworkSettings...")
        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                tunnelLog("Failed to set settings: \(error.localizedDescription)")
                return completionHandler(error)
            }
            tunnelLog("Tunnel network settings set successfully. Starting packet loops.")
            self.setPackets()
            completionHandler(nil)
        }
    }
    
    func setPackets() {
        packetFlow.readPackets { [self] packets, protocols in
            let fakeip = self.fakeIpValue
            let deviceip = self.deviceIpValue
            var modified = packets
            
            for i in modified.indices where protocols[i].int32Value == AF_INET && modified[i].count >= 20 {
                modified[i].withUnsafeMutableBytes { bytes in
                    guard let ptr = bytes.baseAddress?.assumingMemoryBound(to: UInt32.self) else { return }
                    let src = UInt32(bigEndian: ptr[3])
                    let dst = UInt32(bigEndian: ptr[4])
                    
                    if src == deviceip {
                        ptr[3] = fakeip.bigEndian
                    }
                    if dst == fakeip {
                        ptr[4] = deviceip.bigEndian
                    }
                }
            }
            
            self.packetFlow.writePackets(modified, withProtocols: protocols)
            setPackets()
        }
    }

    private func ipToUInt32(_ ipString: String) -> UInt32 {
        let components = ipString.split(separator: ".")
        guard components.count == 4,
              let b1 = UInt32(components[0]),
              let b2 = UInt32(components[1]),
              let b3 = UInt32(components[2]),
              let b4 = UInt32(components[3]) else {
            return 0
        }
        return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
    }

    private func ipToString(_ ip: UInt32) -> String {
        let b1 = (ip >> 24) & 0xFF
        let b2 = (ip >> 16) & 0xFF
        let b3 = (ip >> 8) & 0xFF
        let b4 = ip & 0xFF
        return "\(b1).\(b2).\(b3).\(b4)"
    }
}
