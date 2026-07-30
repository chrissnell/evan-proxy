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
}

/// Async throwing assertion helper.
func XCTAssertThrowsErrorAsync(_ expr: @autoclosure () async throws -> Void,
                               file: StaticString = #filePath, line: UInt = #line) async {
    do { try await expr(); XCTFail("expected error", file: file, line: line) } catch {}
}
