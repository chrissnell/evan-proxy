import Foundation
import Observation
import OpenAPIRuntime
import OpenAPIURLSession
#if canImport(UIKit)
import UIKit
#endif

enum PairingError: Error { case invalidLink, rejected }

@Observable
@MainActor
final class PairingModel {
    var busy = false
    var error: String?
    let auth: AuthStore
    init(auth: AuthStore) { self.auth = auth }

    /// Parse an `evanproxy://pair?host=<host>&code=<code>` deep link.
    nonisolated static func parse(_ url: URL) throws -> (host: String, code: String) {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              comps.scheme == "evanproxy", comps.host == "pair",
              let host = comps.queryItems?.first(where: { $0.name == "host" })?.value, !host.isEmpty,
              let code = comps.queryItems?.first(where: { $0.name == "code" })?.value, !code.isEmpty
        else { throw PairingError.invalidLink }
        return (host, code)
    }

    /// Redeem the enrollment code at `https://<host>/api/pair`, store the bearer
    /// token in the Keychain, and point the app at the paired server.
    func pair(host: String, code: String, deviceName: String? = nil) async throws {
        guard let base = URL(string: "https://\(host)") else { throw PairingError.invalidLink }
        let client = Client(
            serverURL: base,
            transport: URLSessionTransport(configuration: .init(session: APIClientFactory.session))
        )
        let name = deviceName ?? Self.defaultDeviceName
        let resp = try await client.pairDevice(body: .json(.init(code: code, device_name: name)))
        guard case .ok(let ok) = resp else { throw PairingError.rejected }
        let token = try ok.body.json.token
        try auth.storePairing(token: token)
        ServerConfig.baseURL = base
    }

    /// UI entry point: parse a scanned/opened link and pair, mapping failures
    /// to a user-facing message.
    func handle(_ url: URL) async {
        error = nil
        busy = true
        defer { busy = false }
        do {
            let p = try Self.parse(url)
            try await pair(host: p.host, code: p.code)
        } catch PairingError.invalidLink {
            error = "not an evan-proxy pairing code"
        } catch PairingError.rejected {
            error = "code expired or already used — generate a new QR"
        } catch {
            self.error = "connection failed — check network"
        }
    }

    func handle(scanned: String) async {
        guard let url = URL(string: scanned) else {
            error = "not an evan-proxy pairing code"
            return
        }
        await handle(url)
    }

    private static var defaultDeviceName: String {
        #if canImport(UIKit)
        UIDevice.current.name
        #else
        "device"
        #endif
    }
}
