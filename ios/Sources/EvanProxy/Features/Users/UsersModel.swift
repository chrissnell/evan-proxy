import Foundation
import Observation

/// Narrow protocol the Users screen depends on — lets tests stub the network.
@MainActor
protocol UsersAPI {
    func listUsers() async throws -> [Components.Schemas.UserInfo]
    func setEnabled(_ username: String, _ enabled: Bool) async throws
}

/// Adapter mapping the narrow protocol onto the generated Client.
struct LiveUsersAPI: UsersAPI {
    let client: Client
    func listUsers() async throws -> [Components.Schemas.UserInfo] {
        try await client.listUsers().ok.body.json
    }
    func setEnabled(_ username: String, _ enabled: Bool) async throws {
        _ = try await client.setEnabled(body: .json(.init(username: username, enabled: enabled)))
    }
}

@MainActor
protocol UserEditsAPI {
    func setPort(_ username: String, _ port: Int) async throws
    func setDNS(_ username: String, server: String, proto: String) async throws
    func testDNS(server: String, proto: String) async throws -> Bool
    func changePassword(_ username: String, _ password: String) async throws
    func deleteUser(_ username: String) async throws
    func setDowntime(_ username: String, _ schedule: [String: [Components.Schemas.DowntimeWindow]]) async throws
    func setOverride(_ username: String, minutes: Int) async throws
}

extension LiveUsersAPI: UserEditsAPI {
    func setPort(_ username: String, _ port: Int) async throws {
        _ = try await client.setPort(body: .json(.init(username: username, port: port)))
    }
    func setDNS(_ username: String, server: String, proto: String) async throws {
        _ = try await client.setDNS(body: .json(.init(username: username, dns_server: server,
            dns_protocol: .init(rawValue: proto) ?? ._empty)))
    }
    func testDNS(server: String, proto: String) async throws -> Bool {
        let r = try await client.testDNS(body: .json(.init(dns_server: server,
            dns_protocol: .init(rawValue: proto) ?? .plain)))
        return try r.ok.body.json.ok
    }
    func changePassword(_ username: String, _ password: String) async throws {
        _ = try await client.changePassword(body: .json(.init(username: username, password: password)))
    }
    func deleteUser(_ username: String) async throws {
        _ = try await client.deleteUser(query: .init(username: username))
    }
    func setDowntime(_ username: String, _ schedule: [String: [Components.Schemas.DowntimeWindow]]) async throws {
        _ = try await client.setDowntimeSchedule(body: .json(.init(username: username,
            downtime_schedule: .init(additionalProperties: schedule))))
    }
    func setOverride(_ username: String, minutes: Int) async throws {
        _ = try await client.setDowntimeOverride(body: .json(.init(username: username, duration_minutes: minutes)))
    }
}

@Observable @MainActor
final class UsersModel {
    private let api: UsersAPI
    var users: [Components.Schemas.UserInfo] = []
    var error: String?
    init(api: UsersAPI) { self.api = api }

    func load() async {
        do { users = try await api.listUsers(); error = nil }
        catch { self.error = "failed to load users" }
    }
    func setEnabled(_ username: String, _ enabled: Bool) async {
        do { try await api.setEnabled(username, enabled); await load() }
        catch { self.error = "failed to update user" }
    }
}
