import Foundation
import OpenAPIRuntime
import HTTPTypes

/// Attach `Authorization: Bearer <token>` when a device token exists (QR-paired
/// installs). A 401 with a token present means the token was revoked server-side;
/// there is no password to retry with, so surface it via `onRevoked` and let the
/// app return to the pairing screen.
struct BearerAuthMiddleware: ClientMiddleware {
    let token: @Sendable () -> String?
    let onRevoked: @Sendable () async -> Void

    func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        guard let tok = token() else { return try await next(request, body, baseURL) }
        var request = request
        request.headerFields[.authorization] = "Bearer \(tok)"
        let (resp, respBody) = try await next(request, body, baseURL)
        if resp.status.code == 401, operationID != "pairDevice" {
            await onRevoked()
        }
        return (resp, respBody)
    }
}
