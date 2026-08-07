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
    func test_setOverride_callsAPIAndReloads() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        await model.setOverride("evan", minutes: 30)
        XCTAssertEqual(stub.lastOverride?.0, "evan")
        XCTAssertEqual(stub.lastOverride?.1, 30)
        XCTAssertNil(model.error)
    }
    func test_createUser_returnsTrueAndReloads() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        let ok = await model.createUser("mia", "secret")
        XCTAssertTrue(ok)
        XCTAssertEqual(stub.lastCreated?.0, "mia")
    }
    private func sample(_ n: String, enabled: Bool = true) -> Components.Schemas.UserInfo {
        .init(username: n, created_at: "2026-01-01T00:00:00Z", dns_server: "",
              dns_protocol: ._empty, port: 4100, enabled: enabled)
    }
}

final class StubUsersAPI: UsersAPI {
    var users: [Components.Schemas.UserInfo]
    var lastSetEnabled: (String, Bool)?
    var lastOverride: (String, Int)?
    var lastCreated: (String, String)?
    init(users: [Components.Schemas.UserInfo]) { self.users = users }
    func listUsers() async throws -> [Components.Schemas.UserInfo] { users }
    func setEnabled(_ username: String, _ enabled: Bool) async throws { lastSetEnabled = (username, enabled) }
    func setOverride(_ username: String, minutes: Int) async throws { lastOverride = (username, minutes) }
    func createUser(_ username: String, _ password: String) async throws { lastCreated = (username, password) }
}
