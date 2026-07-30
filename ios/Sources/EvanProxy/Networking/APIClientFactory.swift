import Foundation
import OpenAPIRuntime
import OpenAPIURLSession

@MainActor
enum APIClientFactory {
    /// One cookie-persisting URLSession for the whole app (carries evan-proxy-session).
    static let session: URLSession = {
        let cfg = URLSessionConfiguration.default
        cfg.httpCookieStorage = .shared
        cfg.httpCookieAcceptPolicy = .always
        cfg.httpShouldSetCookies = true
        return URLSession(configuration: cfg)
    }()

    /// Build a client bound to the configured server and an AuthStore for reauth.
    static func make(auth: AuthStore) throws -> Client {
        guard let base = ServerConfig.baseURL else { throw AuthError.notConfigured }
        let transport = URLSessionTransport(
            configuration: .init(session: session)
        )
        let client = Client(
            serverURL: base,
            transport: transport,
            middlewares: [ReauthMiddleware { try await auth.reauthenticate() }]
        )
        // Wire AuthStore's login side-effect to a real /api/login call.
        auth.loginFn = { username, password in
            let resp = try await client.login(body: .json(.init(username: username, password: password)))
            switch resp {
            case .ok: return
            default:  throw AuthError.invalidCredentials
            }
        }
        return client
    }
}
