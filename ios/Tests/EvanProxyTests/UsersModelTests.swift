import XCTest
@testable import EvanProxy

@MainActor
final class UsersModelTests: XCTestCase {
    func test_load_populatesUsers() async {
        let model = UsersModel(api: StubUsersAPI(users: [sample("evan"), sample("mia")]))
        await model.load()
        XCTAssertEqual(model.users.map(\.username), ["evan", "mia"])
        XCTAssertNil(model.error)
    }
    func test_toggleEnabled_flipsAndReloads() async {
        let stub = StubUsersAPI(users: [sample("evan", enabled: true)])
        let model = UsersModel(api: stub)
        await model.load()
        await model.setEnabled("evan", false)
        XCTAssertEqual(stub.lastSetEnabled?.0, "evan")
        XCTAssertEqual(stub.lastSetEnabled?.1, false)
    }
    private func sample(_ n: String, enabled: Bool = true) -> Components.Schemas.UserInfo {
        .init(username: n, created_at: "2026-01-01T00:00:00Z", dns_server: "",
              dns_protocol: ._empty, port: 4100, enabled: enabled)
    }
}

final class StubUsersAPI: UsersAPI {
    var users: [Components.Schemas.UserInfo]
    var lastSetEnabled: (String, Bool)?
    init(users: [Components.Schemas.UserInfo]) { self.users = users }
    func listUsers() async throws -> [Components.Schemas.UserInfo] { users }
    func setEnabled(_ username: String, _ enabled: Bool) async throws { lastSetEnabled = (username, enabled) }
}
