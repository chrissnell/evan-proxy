import XCTest
import OpenAPIRuntime
import HTTPTypes
@testable import EvanProxy

final class ReauthMiddlewareTests: XCTestCase {
    func run(_ mw: ReauthMiddleware, statuses: [Int]) async throws -> (HTTPResponse, Int) {
        var idx = 0, calls = 0
        let req = HTTPRequest(method: .get, scheme: "https", authority: "h", path: "/api/users")
        let (resp, _) = try await mw.intercept(
            req, body: nil, baseURL: URL(string: "https://h")!, operationID: "listUsers"
        ) { _, _, _ in
            calls += 1
            let code = statuses[min(idx, statuses.count - 1)]; idx += 1
            return (HTTPResponse(status: .init(code: code)), nil)
        }
        return (resp, calls)
    }

    func test_passesThrough_non401() async throws {
        var reauthed = 0
        let mw = ReauthMiddleware { reauthed += 1 }
        let (resp, calls) = try await run(mw, statuses: [200])
        XCTAssertEqual(resp.status.code, 200)
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(reauthed, 0)
    }

    func test_401_triggersReauth_andRetriesOnce() async throws {
        var reauthed = 0
        let mw = ReauthMiddleware { reauthed += 1 }
        let (resp, calls) = try await run(mw, statuses: [401, 200])
        XCTAssertEqual(reauthed, 1)
        XCTAssertEqual(calls, 2)          // original + one retry
        XCTAssertEqual(resp.status.code, 200)
    }

    func test_stillsFailing_after_retry_returns401_noLoop() async throws {
        var reauthed = 0
        let mw = ReauthMiddleware { reauthed += 1 }
        let (resp, calls) = try await run(mw, statuses: [401, 401])
        XCTAssertEqual(reauthed, 1)
        XCTAssertEqual(calls, 2)          // exactly one retry, no infinite loop
        XCTAssertEqual(resp.status.code, 401)
    }
}
