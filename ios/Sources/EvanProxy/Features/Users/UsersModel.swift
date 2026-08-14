import Foundation
import Observation

/// Narrow protocol the Users screen depends on — lets tests stub the network.
@MainActor
protocol UsersAPI {
    func listUsers() async throws -> [Components.Schemas.UserInfo]
    func setEnabled(_ username: String, _ enabled: Bool) async throws
    func setOverride(_ username: String, minutes: Int) async throws
    func createUser(_ username: String, _ password: String) async throws
}

/// Adapter mapping the narrow protocol onto the generated Client.
/// `.ok`/`.created` accessors throw on documented error statuses (400/401/404/409)
/// so failures surface instead of silently looking like success.
struct LiveUsersAPI: UsersAPI {
    let client: Client
    func listUsers() async throws -> [Components.Schemas.UserInfo] {
        try await client.listUsers().ok.body.json
    }
    func setEnabled(_ username: String, _ enabled: Bool) async throws {
        _ = try await client.setEnabled(body: .json(.init(username: username, enabled: enabled))).ok
    }
    func createUser(_ username: String, _ password: String) async throws {
        _ = try await client.createUser(body: .json(.init(username: username, password: password))).created
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
        _ = try await client.setPort(body: .json(.init(username: username, port: port))).ok
    }
    func setDNS(_ username: String, server: String, proto: String) async throws {
        _ = try await client.setDNS(body: .json(.init(username: username, dns_server: server,
            dns_protocol: .init(rawValue: proto) ?? ._empty))).ok
    }
    func testDNS(server: String, proto: String) async throws -> Bool {
        let r = try await client.testDNS(body: .json(.init(dns_server: server,
            dns_protocol: .init(rawValue: proto) ?? .plain)))
        return try r.ok.body.json.ok
    }
    func changePassword(_ username: String, _ password: String) async throws {
        _ = try await client.changePassword(body: .json(.init(username: username, password: password))).ok
    }
    func deleteUser(_ username: String) async throws {
        _ = try await client.deleteUser(query: .init(username: username)).ok
    }
    func setDowntime(_ username: String, _ schedule: [String: [Components.Schemas.DowntimeWindow]]) async throws {
        _ = try await client.setDowntimeSchedule(body: .json(.init(username: username,
            downtime_schedule: .init(additionalProperties: schedule)))).ok
    }
    func setOverride(_ username: String, minutes: Int) async throws {
        _ = try await client.setDowntimeOverride(body: .json(.init(username: username, duration_minutes: minutes))).ok
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
        catch { self.error = "Failed to load users" }
    }
    func setEnabled(_ username: String, _ enabled: Bool) async {
        do { try await api.setEnabled(username, enabled); await load() }
        catch { self.error = "Failed to update user" }
    }
    func setOverride(_ username: String, minutes: Int) async {
        do { try await api.setOverride(username, minutes: minutes); await load() }
        catch { self.error = "Failed to set override" }
    }
    /// Returns true on success so the add-user sheet knows to dismiss.
    func createUser(_ username: String, _ password: String) async -> Bool {
        do { try await api.createUser(username, password); await load(); return true }
        catch { self.error = "Failed to create user"; return false }
    }
}
