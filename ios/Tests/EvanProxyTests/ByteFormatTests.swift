import XCTest
@testable import EvanProxy

final class ByteFormatTests: XCTestCase {
    func test_bytes_belowKilobyte() {
        XCTAssertEqual(ByteFormat.string(0), "0 B")
        XCTAssertEqual(ByteFormat.string(512), "512 B")
        XCTAssertEqual(ByteFormat.string(1023), "1023 B")
    }
    func test_kilobytes() {
        XCTAssertEqual(ByteFormat.string(1024), "1.0 KB")
        XCTAssertEqual(ByteFormat.string(1536), "1.5 KB")
    }
    func test_megabytes() {
        XCTAssertEqual(ByteFormat.string(1_048_576), "1.0 MB")
    }
    func test_gigabytes() {
        XCTAssertEqual(ByteFormat.string(1_073_741_824), "1.0 GB")
    }
}
