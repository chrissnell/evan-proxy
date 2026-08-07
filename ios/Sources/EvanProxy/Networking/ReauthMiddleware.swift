import Foundation
import OpenAPIRuntime
import HTTPTypes

/// On a 401, run `reauth` once and retry the request a single time.
struct ReauthMiddleware: ClientMiddleware {
    let reauth: @Sendable () async throws -> Void

    func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        let (resp, respBody) = try await next(request, body, baseURL)
        guard resp.status.code == 401, operationID != "login" else { return (resp, respBody) }
        do { try await reauth() } catch { return (resp, respBody) }   // reauth failed → surface original 401
        return try await next(request, body, baseURL)                 // retry exactly once
    }
}
