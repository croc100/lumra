// LumraApp — the standalone monitoring app UI (host mode B). It starts/stops the
// monitor-only tunnel via NETunnelProviderManager and renders the live board the
// extension publishes. Diagnosis only: the app shows who is blocking/watching/
// down; it never reroutes.

import SwiftUI
import NetworkExtension

@main
struct LumraApp: App {
    var body: some Scene {
        WindowGroup { BoardView() }
    }
}

struct BoardView: View {
    @StateObject private var model = BoardViewModel()

    var body: some View {
        NavigationView {
            List(model.rows) { row in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(row.badge)
                        Text(row.domain).font(.headline)
                        Spacer()
                        Text(row.tls).font(.caption).foregroundColor(.secondary)
                    }
                    Text(row.status).font(.subheadline)
                    if let who = row.who { Text("who: \(who)").font(.caption).foregroundColor(.secondary) }
                    if let why = row.why { Text("why: \(why)").font(.caption).foregroundColor(.secondary) }
                }
                .listRowBackground(color(for: row.nature))
            }
            .navigationTitle("Lumra — \(model.rows.count) domains")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(model.running ? "Stop" : "Start") { model.toggle() }
                }
            }
        }
        .onAppear { model.load() }
    }

    private func color(for nature: String) -> Color {
        switch nature {
        case "control": return Color.red.opacity(0.12)
        case "surveillance": return Color.purple.opacity(0.12)
        case "degradation": return Color.orange.opacity(0.12)
        case "fault": return Color.yellow.opacity(0.12)
        default: return Color.clear
        }
    }
}

@MainActor
final class BoardViewModel: ObservableObject {
    @Published var rows: [BoardRow] = []
    @Published var running = false

    private let reader = BoardReader()
    private var manager: NETunnelProviderManager?
    private var timer: Timer?

    func load() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            let mgr = managers?.first ?? NETunnelProviderManager()
            self?.manager = mgr
            self?.running = mgr.connection.status == .connected
            self?.startPolling()
        }
    }

    func toggle() {
        running ? stop() : start()
    }

    private func start() {
        guard let manager = manager else { return }
        let proto = NETunnelProviderProtocol()
        // Bundle id of the packet-tunnel extension target.
        proto.providerBundleIdentifier = "net.crode.lumra.tunnel"
        proto.serverAddress = "Lumra (monitor-only)"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Lumra"
        manager.isEnabled = true
        manager.saveToPreferences { [weak self] _ in
            manager.loadFromPreferences { _ in
                try? manager.connection.startVPNTunnel()
                self?.running = true
            }
        }
    }

    private func stop() {
        manager?.connection.stopVPNTunnel()
        running = false
    }

    private func startPolling() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.rows = self.reader.read()
        }
    }
}
