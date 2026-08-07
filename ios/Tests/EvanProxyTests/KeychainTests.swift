import XCTest
@testable import EvanProxy

final class KeychainTests: XCTestCase {
    let kc = Keychain(service: "com.evanproxy.tests")

    override func tearDown() { try? kc.remove("creds"); super.tearDown() }

    func test_setAndGet_roundtrips() throws {
        try kc.set("hunter2", for: "creds")
        XCTAssertEqual(try kc.get("creds"), "hunter2")
    }

    func test_get_missing_returnsNil() throws {
        XCTAssertNil(try kc.get("nope"))
    }

    func test_remove_clears() throws {
        try kc.set("x", for: "creds")
        try kc.remove("creds")
        XCTAssertNil(try kc.get("creds"))
    }
}
