import XCTest
@testable import EvanProxy

@MainActor
final class AuthStoreTests: XCTestCase {
    let testKeychain = Keychain(service: "com.evanproxy.authtests")
    func makeStore(hasServerConfig: @escaping () -> Bool = { true }) -> AuthStore {
        AuthStore(keychain: testKeychain, hasServerConfig: hasServerConfig)
    }
    override func tearDown() {
        try? testKeychain.remove("username")
        try? testKeychain.remove("password")
        try? testKeychain.remove("deviceToken")
        super.tearDown()
    }

    func test_init_scrubsLegacyPasswordCredentials() throws {
        try testKeychain.set("evan", for: "username")
        try testKeychain.set("pw", for: "password")
        _ = makeStore()
        XCTAssertNil(try testKeychain.get("username"))
        XCTAssertNil(try testKeychain.get("password"))
    }

    func test_init_scrubsLegacySessionCookies() throws {
        let cookie = HTTPCookie(properties: [.domain: "proxy.example.com", .path: "/",
                                             .name: "evan-proxy-session", .value: "legacy"])!
        HTTPCookieStorage.shared.setCookie(cookie)
        _ = makeStore()
        let remaining = HTTPCookieStorage.shared.cookies ?? []
        XCTAssertFalse(remaining.contains { $0.name == "evan-proxy-session" })
    }

    func test_resumePairedSession_orphanedToken_withoutServerConfig_scrubsToken() throws {
        // Keychain outlives app deletion; UserDefaults doesn't. A reinstall
        // must land on pairing, not authenticate against a missing server.
        try testKeychain.set("orphan", for: "deviceToken")
        let store = makeStore(hasServerConfig: { false })
        store.resumePairedSession()
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertNil(store.currentDeviceToken())
    }

    func test_storePairing_storesToken_marksAuthenticated() throws {
        let store = makeStore()
        XCTAssertFalse(store.isAuthenticated)
        try store.storePairing(token: "tok123")
        XCTAssertTrue(store.isAuthenticated)
        XCTAssertTrue(store.hasDeviceToken)
        XCTAssertEqual(store.currentDeviceToken(), "tok123")
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
}
