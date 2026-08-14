import Foundation
import Observation
import OpenAPIRuntime
import OpenAPIURLSession
#if canImport(UIKit)
import UIKit
#endif

enum PairingError: Error { case invalidLink, rejected }

/// A parsed pairing link awaiting user confirmation.
struct PendingPair: Equatable, Sendable {
    let host: String
    let code: String
    let scheme: String

    init(host: String, code: String, scheme: String = "https") {
        self.host = host
        self.code = code
        self.scheme = scheme
    }

    var baseURLString: String { "\(scheme)://\(host)" }
}

@Observable
@MainActor
final class PairingModel {
    var busy = false
    var error: String?
    var pending: PendingPair?
    let auth: AuthStore
    init(auth: AuthStore) { self.auth = auth }

    /// Parse an `evanproxy://pair?host=<host>&code=<code>[&scheme=http|https]`
    /// deep link. The optional scheme lets plain-http servers pair; anything
    /// but the two known values is rejected outright.
    nonisolated static func parse(_ url: URL) throws -> PendingPair {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              comps.scheme == "evanproxy", comps.host == "pair",
              let host = comps.queryItems?.first(where: { $0.name == "host" })?.value,
              let code = comps.queryItems?.first(where: { $0.name == "code" })?.value, !code.isEmpty,
              isValidHost(host)
        else { throw PairingError.invalidLink }
        let scheme = comps.queryItems?.first(where: { $0.name == "scheme" })?.value ?? "https"
        guard scheme == "https" || scheme == "http" else { throw PairingError.invalidLink }
        return PendingPair(host: host, code: code, scheme: scheme)
    }

    /// host:port only — reject anything that could smuggle a path, userinfo,
    /// query, or a percent-encoded version of those into the https URL built
    /// from it. (`%` never appears in a legit host: the QR path pre-decodes.)
    nonisolated static func isValidHost(_ host: String) -> Bool {
        !host.isEmpty
            && !host.contains(where: { "/@?#% \\".contains($0) })
            && URL(string: "https://\(host)")?.host() != nil
    }

    /// Redeem the enrollment code at `<scheme>://<host>/api/pair`, store the
    /// bearer token in the Keychain, and point the app at the paired server.
    /// The user just confirmed this exact server, so the TOFU window opens for
    /// its host: a self-signed certificate seen here gets pinned; afterwards
    /// only that certificate is accepted.
    func pair(_ p: PendingPair, deviceName: String? = nil) async throws {
        guard let base = URL(string: p.baseURLString), let pinHost = base.host()
        else { throw PairingError.invalidLink }
        APIClientFactory.trustDelegate.beginPairing(host: pinHost)
        defer { APIClientFactory.trustDelegate.endPairing() }
        let client = Client(
            serverURL: base,
            transport: URLSessionTransport(configuration: .init(session: APIClientFactory.session))
        )
        let name = deviceName ?? Self.defaultDeviceName
        let resp = try await client.pairDevice(body: .json(.init(code: p.code, device_name: name)))
        guard case .ok(let ok) = resp else { throw PairingError.rejected }
        let token = try ok.body.json.token
        // Config before credential: isAuthenticated must never be observable
        // while the base URL is still unset (that dead-ends on a blank screen).
        ServerConfig.baseURL = base
        try auth.storePairing(token: token)
    }

    /// UI entry point: parse a scanned/opened link and stage it for user
    /// confirmation. Pairing repoints the app and drops existing credentials,
    /// so a bare deep-link tap must never trigger it directly.
    func handle(_ url: URL) async {
        error = nil
        do {
            pending = try Self.parse(url)
        } catch {
            self.error = "Not an evan-proxy pairing code"
        }
    }

    /// Run a user-confirmed pairing, mapping failures to a user-facing message.
    /// Takes the value (not `pending`) so alert dismissal order can't race it.
    func confirm(_ p: PendingPair) async {
        pending = nil
        error = nil
        busy = true
        defer { busy = false }
        do {
            try await pair(p)
        } catch PairingError.invalidLink {
            error = "Not an evan-proxy pairing code"
        } catch PairingError.rejected {
            error = "Code expired or already used — generate a new QR"
        } catch {
            self.error = "Connection failed — check network"
        }
    }

    func cancelPending() { pending = nil }

    /// Manual fallback for when the camera is unavailable or declined.
    /// Validates typed input, forgiving pasted extras (whitespace, an
    /// `https://`/`http://` prefix, trailing slashes). Returns nil if invalid.
    /// Stages nothing — the sheet calls `stage(_:)` after it has dismissed,
    /// because setting `pending` mid-dismissal can drop the confirmation alert.
    nonisolated static func validateManual(host rawHost: String, code rawCode: String) -> PendingPair? {
        var host = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
        var scheme = "https"
        for prefix in ["https://", "http://"] where host.lowercased().hasPrefix(prefix) {
            // A typed http:// is meaningful — the server really is plain http.
            if prefix == "http://" { scheme = "http" }
            host = String(host.dropFirst(prefix.count))
            break
        }
        while host.hasSuffix("/") { host = String(host.dropLast()) }
        let code = rawCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidHost(host), !code.isEmpty else { return nil }
        return PendingPair(host: host, code: code, scheme: scheme)
    }

    /// Stage a validated manual pair for the same user confirmation a scanned
    /// link gets.
    func stage(_ p: PendingPair) {
        error = nil
        pending = p
    }

    func handle(scanned: String) async {
        guard let url = URL(string: scanned) else {
            error = "Not an evan-proxy pairing code"
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
