import XCTest
@testable import EvanProxy

final class LogStreamTests: XCTestCase {
    func test_parsesDataFrames_intoEntries() async throws {
        let sse = "data: {\"ts\":\"2026-07-30T14:02:11Z\",\"event\":\"open\",\"status\":200}\n\n" +
                  "data: {\"ts\":\"2026-07-30T14:02:12Z\",\"event\":\"dns-block\",\"status\":523}\n\n"
        var events: [Components.Schemas.LogEntry] = []
        for try await e in SSEParser.entries(from: linesOf(sse)) { events.append(e) }
        XCTAssertEqual(events.count, 2)
        XCTAssertEqual(events[1].status, 523)
    }
    // Yields the SSE text as an async line sequence.
    private func linesOf(_ s: String) -> AsyncStream<String> {
        AsyncStream { cont in for l in s.split(separator: "\n", omittingEmptySubsequences: false) { cont.yield(String(l)) }; cont.finish() }
    }
}
