import XCTest
@testable import EvanProxy

final class GeneratedClientSmokeTests: XCTestCase {
    func test_generatedTypes_exist() {
        let user = Components.Schemas.UserInfo(
            username: "evan", created_at: "2026-01-01T00:00:00Z",
            dns_server: "", dns_protocol: .init(rawValue: "")!, port: 4100, enabled: true)
        XCTAssertEqual(user.username, "evan")
    }
}
