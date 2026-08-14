import XCTest
@testable import EvanProxy

@MainActor
final class AuthStoreTests: XCTestCase {
    func makeStore() -> AuthStore {
        AuthStore(keychain: Keychain(service: "com.evanproxy.authtests"))
    }
    override func tearDown() {
        try? Keychain(service: "com.evanproxy.authtests").remove("username")
        try? Keychain(service: "com.evanproxy.authtests").remove("password")
        try? Keychain(service: "com.evanproxy.authtests").remove("deviceToken")
        super.tearDown()
    }

    func test_login_success_storesCredentials_andMarksAuthenticated() async throws {
        let store = makeStore()
        var called = 0
        store.loginFn = { u, p in called += 1; XCTAssertEqual(u, "evan"); XCTAssertEqual(p, "pw") }
        try await store.login(username: "evan", password: "pw")
        XCTAssertEqual(called, 1)
        XCTAssertTrue(store.isAuthenticated)
        XCTAssertTrue(store.hasStoredCredentials)
    }

    func test_login_failure_doesNotStore() async {
        let store = makeStore()
        store.loginFn = { _, _ in throw AuthError.invalidCredentials }
        await XCTAssertThrowsErrorAsync(try await store.login(username: "x", password: "y"))
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertFalse(store.hasStoredCredentials)
    }

    func test_reauthenticate_usesStoredCredentials() async throws {
        let store = makeStore()
        store.loginFn = { _, _ in }
        try await store.login(username: "evan", password: "pw")
        var reauthUser: String?
        store.loginFn = { u, _ in reauthUser = u }
        try await store.reauthenticate()
        XCTAssertEqual(reauthUser, "evan")
    }

    func test_reauthenticate_withNoCredentials_throws() async {
        let store = makeStore()
        await XCTAssertThrowsErrorAsync(try await store.reauthenticate())
    }

    func test_logout_clearsCredentials() async throws {
        let store = makeStore()
        store.loginFn = { _, _ in }
        try await store.login(username: "evan", password: "pw")
        store.logout()
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertFalse(store.hasStoredCredentials)
    }

    func test_storePairing_storesToken_dropsPassword_marksAuthenticated() async throws {
        let store = makeStore()
        store.loginFn = { _, _ in }
        try await store.login(username: "evan", password: "pw")   // legacy install
        try store.storePairing(token: "tok123")
        XCTAssertTrue(store.isAuthenticated)
        XCTAssertTrue(store.hasDeviceToken)
        XCTAssertEqual(store.currentDeviceToken(), "tok123")
        XCTAssertFalse(store.hasStoredCredentials)                // password is gone
    }

    func test_unpair_clearsToken_andUnauthenticates() throws {
        let store = makeStore()
        try store.storePairing(token: "tok123")
        store.unpair()
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertFalse(store.hasDeviceToken)
        XCTAssertNil(store.currentDeviceToken())
    }

    func test_resumePairedSession_authenticatesOnlyWithToken() throws {
        let store = makeStore()
        store.resumePairedSession()
        XCTAssertFalse(store.isAuthenticated)     // nothing stored yet
        try store.storePairing(token: "tok123")
        store.unpair()
        store.resumePairedSession()
        XCTAssertFalse(store.isAuthenticated)     // unpaired
        try store.storePairing(token: "tok456")
        store.resumePairedSession()
        XCTAssertTrue(store.isAuthenticated)
    }

    func test_logout_alsoClearsDeviceToken() throws {
        let store = makeStore()
        try store.storePairing(token: "tok123")
        store.logout()
        XCTAssertFalse(store.hasDeviceToken)
    }
}

/// Async throwing assertion helper.
func XCTAssertThrowsErrorAsync(_ expr: @autoclosure () async throws -> Void,
                               file: StaticString = #filePath, line: UInt = #line) async {
    do { try await expr(); XCTFail("expected error", file: file, line: line) } catch {}
}
