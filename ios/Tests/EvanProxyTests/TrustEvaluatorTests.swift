import XCTest
@testable import EvanProxy

final class TrustEvaluatorTests: XCTestCase {
    func test_systemTrusted_alwaysAllowed() {
        XCTAssertEqual(
            TrustEvaluator.evaluate(systemTrusted: true, presented: "aa", pinned: nil, mayPin: false),
            .allowSystemTrusted)
        XCTAssertEqual(
            TrustEvaluator.evaluate(systemTrusted: true, presented: "aa", pinned: "bb", mayPin: true),
            .allowSystemTrusted)
    }

    func test_untrusted_matchingPin_allowed() {
        XCTAssertEqual(
            TrustEvaluator.evaluate(systemTrusted: false, presented: "aa", pinned: "aa", mayPin: false),
            .allowPinned)
    }

    func test_untrusted_mismatchedPin_rejected_evenDuringPairing() {
        XCTAssertEqual(
            TrustEvaluator.evaluate(systemTrusted: false, presented: "aa", pinned: "bb", mayPin: true),
            .reject)
    }

    func test_untrusted_noPin_onlyPinsDuringUserConfirmedPairing() {
        XCTAssertEqual(
            TrustEvaluator.evaluate(systemTrusted: false, presented: "aa", pinned: nil, mayPin: true),
            .allowAndPin)
        XCTAssertEqual(
            TrustEvaluator.evaluate(systemTrusted: false, presented: "aa", pinned: nil, mayPin: false),
            .reject)
    }
}
