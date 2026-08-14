import XCTest
@testable import EvanProxy

final class ScannerGateTests: XCTestCase {
    func test_missingUsageDescription_blocksScanner() {
        XCTAssertEqual(ScannerGate.evaluate(usageDescription: nil, hasCamera: true),
                       .missingUsageDescription)
    }

    func test_emptyUsageDescription_blocksScanner() {
        XCTAssertEqual(ScannerGate.evaluate(usageDescription: "", hasCamera: true),
                       .missingUsageDescription)
    }

    func test_whitespaceOnlyUsageDescription_blocksScanner() {
        XCTAssertEqual(ScannerGate.evaluate(usageDescription: "  \n ", hasCamera: true),
                       .missingUsageDescription)
    }

    func test_noCamera_reportsNoCamera() {
        XCTAssertEqual(ScannerGate.evaluate(usageDescription: "scan the pairing QR", hasCamera: false),
                       .noCamera)
    }

    func test_usableCamera_isReady() {
        XCTAssertEqual(ScannerGate.evaluate(usageDescription: "scan the pairing QR", hasCamera: true),
                       .ready)
    }

    // A stale plist is the actionable problem even on a camera-less simulator:
    // fixing it is what stops the TCC crash on real devices too.
    func test_missingUsageDescription_winsOverMissingCamera() {
        XCTAssertEqual(ScannerGate.evaluate(usageDescription: nil, hasCamera: false),
                       .missingUsageDescription)
    }
}
