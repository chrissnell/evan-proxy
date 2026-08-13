import XCTest
@testable import EvanProxy

final class PairingModelTests: XCTestCase {
    func testParsePairURL() throws {
        let url = URL(string: "evanproxy://pair?host=proxy.example.com&code=abc123")!
        let p = try PairingModel.parse(url)
        XCTAssertEqual(p.host, "proxy.example.com")
        XCTAssertEqual(p.code, "abc123")
    }

    func testParsePairURL_hostWithPort() throws {
        let url = URL(string: "evanproxy://pair?host=proxy.example.com%3A8443&code=xyz")!
        let p = try PairingModel.parse(url)
        XCTAssertEqual(p.host, "proxy.example.com:8443")
        XCTAssertEqual(p.code, "xyz")
    }

    func testParsePairURL_wrongScheme_throws() {
        let url = URL(string: "https://pair?host=proxy.example.com&code=abc123")!
        XCTAssertThrowsError(try PairingModel.parse(url))
    }

    func testParsePairURL_wrongHost_throws() {
        let url = URL(string: "evanproxy://other?host=proxy.example.com&code=abc123")!
        XCTAssertThrowsError(try PairingModel.parse(url))
    }

    func testParsePairURL_missingCode_throws() {
        let url = URL(string: "evanproxy://pair?host=proxy.example.com")!
        XCTAssertThrowsError(try PairingModel.parse(url))
    }

    func testParsePairURL_missingHost_throws() {
        let url = URL(string: "evanproxy://pair?code=abc123")!
        XCTAssertThrowsError(try PairingModel.parse(url))
    }
}
