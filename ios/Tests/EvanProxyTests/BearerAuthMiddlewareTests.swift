import XCTest
import OpenAPIRuntime
import HTTPTypes
@testable import EvanProxy

final class BearerAuthMiddlewareTests: XCTestCase {
    func run(_ mw: BearerAuthMiddleware, status: Int, operationID: String = "listUsers")
        async throws -> (HTTPResponse, HTTPRequest?) {
        var seen: HTTPRequest?
        let req = HTTPRequest(method: .get, scheme: "https", authority: "h", path: "/api/users")
        let (resp, _) = try await mw.intercept(
            req, body: nil, baseURL: URL(string: "https://h")!, operationID: operationID
        ) { sent, _, _ in
            seen = sent
            return (HTTPResponse(status: .init(code: status)), nil)
        }
        return (resp, seen)
    }

    func test_noToken_passesThroughWithoutHeader() async throws {
        var revoked = 0
        let mw = BearerAuthMiddleware(token: { nil }, onRevoked: { revoked += 1 })
        let (resp, sent) = try await run(mw, status: 401)
        XCTAssertNil(sent?.headerFields[.authorization])
        XCTAssertEqual(resp.status.code, 401)
        XCTAssertEqual(revoked, 0)          // no token → a 401 is not a revocation
    }

    func test_token_setsBearerHeader() async throws {
        let mw = BearerAuthMiddleware(token: { "tok123" }, onRevoked: {})
        let (resp, sent) = try await run(mw, status: 200)
        XCTAssertEqual(sent?.headerFields[.authorization], "Bearer tok123")
        XCTAssertEqual(resp.status.code, 200)
    }

    func test_token_401_firesOnRevoked() async throws {
        var revoked = 0
        let mw = BearerAuthMiddleware(token: { "tok123" }, onRevoked: { revoked += 1 })
        let (resp, _) = try await run(mw, status: 401)
        XCTAssertEqual(revoked, 1)
        XCTAssertEqual(resp.status.code, 401)  // surfaced, not retried — no password to retry with
    }

    func test_token_401_onPairOperation_doesNotRevoke() async throws {
        var revoked = 0
        let mw = BearerAuthMiddleware(token: { "tok123" }, onRevoked: { revoked += 1 })
        _ = try await run(mw, status: 401, operationID: "pairDevice")
        XCTAssertEqual(revoked, 0)
    }
}
