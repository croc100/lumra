// PacketTunnelProvider — the Network Extension that runs Lumra's monitor-only
// tunnel (host mode B: standalone monitoring, no circumvention). It claims the
// OS's packet flow, reads every IP packet, hands it to the Lumra cockpit for
// diagnosis, and writes it straight back out untouched. Lumra observes; it never
// holds, modifies, routes, or re-injects — routing around blocks is warren's job.
//
// This file is the on-device seam to the gomobile-built core. Import the binding
// produced by:
//   gomobile bind -target=ios -o Lumra.xcframework github.com/croc100/lumra/mobile
// and add Lumra.xcframework to this extension target. `Mobile` below is the
// gomobile-generated module (the package name capitalised); MobileCockpit is the
// generated wrapper for mobile.Cockpit.

import NetworkExtension
import Mobile

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var cockpit: MobileCockpit?
    private let board = BoardBridge()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        cockpit = MobileNewCockpit()

        // A monitor-only tunnel: capture all traffic so Lumra sees it, then pass
        // it straight through. No exit server, no rewriting — observe-only.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.111.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: ["fd00:111::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        // Use public resolvers so DNS still flows through the captured path where
        // Lumra can passively read the answers.
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error { completionHandler(error); return }
            self?.readLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        cockpit = nil
        completionHandler()
    }

    // readLoop pulls packets, feeds each to the cockpit for diagnosis, and writes
    // them back unchanged. Recurses to keep draining the flow.
    private func readLoop() {
        packetFlow.readPacketObjects { [weak self] packets in
            guard let self = self, let cockpit = self.cockpit else { return }
            for packet in packets {
                cockpit.feed(packet.data) // observe — Lumra reads IP metadata only
            }
            self.packetFlow.writePacketObjects(packets) // pass through, untouched
            self.board.publish(cockpit.boardJSON())     // share the board with the app UI
            self.readLoop()
        }
    }
}
