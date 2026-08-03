import Foundation
import Observation

/// Narrow protocol the Dashboard depends on — lets tests stub the network.
@MainActor
protocol StatsAPI {
    func topSites() async throws -> [Components.Schemas.HostCount]
    func topBlocked() async throws -> [Components.Schemas.HostCount]
    func traffic() async throws -> [Components.Schemas.TrafficBucket]
}

/// Adapter mapping the narrow protocol onto the generated Client.
struct LiveStatsAPI: StatsAPI {
    let client: Client
    func topSites() async throws -> [Components.Schemas.HostCount] {
        try await client.getTopSites().ok.body.json
    }
    func topBlocked() async throws -> [Components.Schemas.HostCount] {
        try await client.getTopBlocked().ok.body.json
    }
    func traffic() async throws -> [Components.Schemas.TrafficBucket] {
        try await client.getTraffic().ok.body.json
    }
}

@Observable @MainActor
final class DashboardModel {
    private let api: StatsAPI
    var topSites: [Components.Schemas.HostCount] = []
    var topBlocked: [Components.Schemas.HostCount] = []
    var buckets: [Components.Schemas.TrafficBucket] = []
    private var statsTask: Task<Void, Never>?
    private var trafficTask: Task<Void, Never>?
    init(api: StatsAPI) { self.api = api }

    func start() {
        // Poll like the web UI: stats every 5s, traffic every 10s.
        statsTask = Task {
            while !Task.isCancelled {
                if let s = try? await api.topSites() { topSites = s }
                if let b = try? await api.topBlocked() { topBlocked = b }
                try? await Task.sleep(for: .seconds(5))
            }
        }
        trafficTask = Task {
            while !Task.isCancelled {
                if let t = try? await api.traffic() { buckets = t }
                try? await Task.sleep(for: .seconds(10))
            }
        }
    }
    func stop() {
        statsTask?.cancel(); trafficTask?.cancel()
    }
}
