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

    func testParsePairURL_hostWithPath_throws() {
        let url = URL(string: "evanproxy://pair?host=evil.example%2Fpath&code=abc")!
        XCTAssertThrowsError(try PairingModel.parse(url))
    }

    func testParsePairURL_hostWithUserinfo_throws() {
        let url = URL(string: "evanproxy://pair?host=user%40evil.example&code=abc")!
        XCTAssertThrowsError(try PairingModel.parse(url))
    }

    // MARK: Confirmation staging — a link must never pair without user consent

    @MainActor
    private func makeModel() -> PairingModel {
        PairingModel(auth: AuthStore(keychain: Keychain(service: "com.evanproxy.pairtests")))
    }

    @MainActor
    func test_handle_validLink_stagesPendingInsteadOfPairing() async {
        let model = makeModel()
        await model.handle(URL(string: "evanproxy://pair?host=proxy.example.com&code=abc123")!)
        XCTAssertEqual(model.pending, PendingPair(host: "proxy.example.com", code: "abc123"))
        XCTAssertNil(model.error)
        XCTAssertFalse(model.auth.hasDeviceToken)   // nothing paired yet
    }

    @MainActor
    func test_handle_invalidLink_setsError_noPending() async {
        let model = makeModel()
        await model.handle(URL(string: "https://not-a-pair-link.example")!)
        XCTAssertNil(model.pending)
        XCTAssertNotNil(model.error)
    }

    @MainActor
    func test_cancelPending_clearsStagedPair() async {
        let model = makeModel()
        await model.handle(URL(string: "evanproxy://pair?host=proxy.example.com&code=abc123")!)
        model.cancelPending()
        XCTAssertNil(model.pending)
    }
}
