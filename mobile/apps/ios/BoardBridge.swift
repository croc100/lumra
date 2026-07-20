// BoardBridge carries the live board across the process boundary. A
// NEPacketTunnelProvider runs in its own extension process, separate from the
// app UI, so the two share state through an App Group container: the provider
// writes the latest BoardJSON to a shared file, the app reads it. Configure the
// same App Group id on both targets' entitlements and set it below.

import Foundation

enum AppGroup {
    // Replace with your registered App Group identifier (both targets).
    static let identifier = "group.net.crode.lumra"
    static let boardFile = "board.json"
}

/// Written by the extension.
struct BoardBridge {
    private let url: URL? = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: AppGroup.identifier)?
        .appendingPathComponent(AppGroup.boardFile)

    func publish(_ json: Data) {
        guard let url = url else { return }
        try? json.write(to: url, options: .atomic)
    }
}

/// Read by the app UI.
struct BoardReader {
    private let url: URL? = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: AppGroup.identifier)?
        .appendingPathComponent(AppGroup.boardFile)

    func read() -> [BoardRow] {
        guard let url = url, let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([BoardRow].self, from: data)) ?? []
    }
}

/// One row of the cockpit — mirrors internal/live.Row's JSON shape exactly.
struct BoardRow: Decodable, Identifiable {
    let domain: String
    let nature: String
    let badge: String
    let tls: String
    let status: String
    let who: String?
    let why: String?
    let action: String?
    let enforced: String?

    var id: String { domain }
}
