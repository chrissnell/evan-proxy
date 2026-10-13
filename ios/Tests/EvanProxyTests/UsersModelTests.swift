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
    func test_setDowntimeNow_callsAPIAndReloads() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        await model.setDowntimeNow("evan", minutes: 180)
        XCTAssertEqual(stub.lastDowntimeNow?.0, "evan")
        XCTAssertEqual(stub.lastDowntimeNow?.1, 180)
        XCTAssertNil(model.error)
    }
    func test_endDowntimeNow_sendsZeroMinutes() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        await model.setDowntimeNow("evan", minutes: 0)
        XCTAssertEqual(stub.lastDowntimeNow?.1, 0)
    }
    func test_setDowntimeNow_failureSurfacesError() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        stub.failDowntimeNow = true
        let model = UsersModel(api: stub)
        await model.setDowntimeNow("evan", minutes: 60)
        XCTAssertEqual(model.error, "Failed to start downtime")
    }
    func test_start_loadsImmediatelyThenStops() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        model.start()
        await settle(model)
        model.stop()
        XCTAssertEqual(model.users.map(\.username), ["evan"])
        XCTAssertEqual(stub.listCount, 1, "the 30s poll must not fire again straight away")
    }
    func test_start_doesNotStackPollers() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        model.start()
        model.start()
        await settle(model)
        model.stop()
        XCTAssertEqual(stub.listCount, 1)
    }
    func test_createUser_returnsTrueAndReloads() async {
        let stub = StubUsersAPI(users: [sample("evan")])
        let model = UsersModel(api: stub)
        let ok = await model.createUser("mia", "secret")
        XCTAssertTrue(ok)
        XCTAssertEqual(stub.lastCreated?.0, "mia")
    }
    /// Yields until the poller's first load has landed on the main actor.
    private func settle(_ model: UsersModel) async {
        for _ in 0..<100 {
            if !model.users.isEmpty { return }
            await Task.yield()
        }
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
    var lastDowntimeNow: (String, Int)?
    var lastCreated: (String, String)?
    var failDowntimeNow = false
    var listCount = 0
    init(users: [Components.Schemas.UserInfo]) { self.users = users }
    func listUsers() async throws -> [Components.Schemas.UserInfo] { listCount += 1; return users }
    func setEnabled(_ username: String, _ enabled: Bool) async throws { lastSetEnabled = (username, enabled) }
    func setOverride(_ username: String, minutes: Int) async throws { lastOverride = (username, minutes) }
    func setDowntimeNow(_ username: String, minutes: Int) async throws {
        if failDowntimeNow { throw StubError.failed }
        lastDowntimeNow = (username, minutes)
    }
    func createUser(_ username: String, _ password: String) async throws { lastCreated = (username, password) }

    enum StubError: Error { case failed }
}
