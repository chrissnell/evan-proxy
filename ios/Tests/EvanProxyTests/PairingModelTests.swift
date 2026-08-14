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

    // MARK: Manual entry — camera-free fallback goes through the same staging

    func test_validateManual_valid_returnsPair() {
        let p = PairingModel.validateManual(host: "proxy.example.com:8443", code: "abc123")
        XCTAssertEqual(p, PendingPair(host: "proxy.example.com:8443", code: "abc123"))
    }

    func test_validateManual_forgivesWhitespaceSchemeAndTrailingSlash() {
        XCTAssertEqual(
            PairingModel.validateManual(host: "  https://proxy.example.com/  ", code: " abc123\n"),
            PendingPair(host: "proxy.example.com", code: "abc123"))
        XCTAssertEqual(
            PairingModel.validateManual(host: "http://proxy.example.com", code: "abc"),
            PendingPair(host: "proxy.example.com", code: "abc"))
    }

    func test_validateManual_rejectsUnsafeHosts() {
        XCTAssertNil(PairingModel.validateManual(host: "evil.example/path", code: "abc"))
        XCTAssertNil(PairingModel.validateManual(host: "user@evil.example", code: "abc"))
        // Percent-encoding must not slip past the literal blacklist.
        XCTAssertNil(PairingModel.validateManual(host: "evil.example%2Fpath", code: "abc"))
        XCTAssertNil(PairingModel.validateManual(host: "user%40evil.example", code: "abc"))
    }

    func test_validateManual_rejectsEmptyOrDegenerateInput() {
        XCTAssertNil(PairingModel.validateManual(host: "", code: ""))
        XCTAssertNil(PairingModel.validateManual(host: "proxy.example.com", code: "   "))
        // Reduces to empty after forgiveness.
        XCTAssertNil(PairingModel.validateManual(host: "https:///", code: "abc"))
    }

    @MainActor
    func test_stage_setsPending_clearsError_doesNotPair() {
        let model = makeModel()
        model.error = "stale scan error"
        model.stage(PendingPair(host: "proxy.example.com", code: "abc123"))
        XCTAssertEqual(model.pending, PendingPair(host: "proxy.example.com", code: "abc123"))
        XCTAssertNil(model.error)
        XCTAssertFalse(model.auth.hasDeviceToken)   // still needs confirmation
    }
}
