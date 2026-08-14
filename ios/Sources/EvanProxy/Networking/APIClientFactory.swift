import Foundation
import OpenAPIRuntime
import OpenAPIURLSession

@MainActor
enum APIClientFactory {
    /// One URLSession shared by the generated client, pairing, and the SSE log
    /// stream — so the TOFU trust delegate governs every connection.
    static let trustDelegate = TOFUSessionDelegate()
    static let session = URLSession(configuration: .default, delegate: trustDelegate, delegateQueue: nil)

    /// Build a client bound to the paired server, authenticating with the
    /// device bearer token.
    static func make(auth: AuthStore) throws -> Client {
        guard let base = ServerConfig.baseURL else { throw AuthError.notConfigured }
        return Client(
            serverURL: base,
            transport: URLSessionTransport(configuration: .init(session: session)),
            middlewares: [
                // A 401 means the token was revoked — unpair back to the
                // pairing screen; there is no password fallback on the device.
                BearerAuthMiddleware(
                    token: { auth.currentDeviceToken() },
                    onRevoked: { await auth.unpair() }
                )
            ]
        )
    }
}
