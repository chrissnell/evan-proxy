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
}

@Observable
@MainActor
final class PairingModel {
    var busy = false
    var error: String?
    var pending: PendingPair?
    let auth: AuthStore
    init(auth: AuthStore) { self.auth = auth }

    /// Parse an `evanproxy://pair?host=<host>&code=<code>` deep link.
    nonisolated static func parse(_ url: URL) throws -> (host: String, code: String) {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              comps.scheme == "evanproxy", comps.host == "pair",
              let host = comps.queryItems?.first(where: { $0.name == "host" })?.value,
              let code = comps.queryItems?.first(where: { $0.name == "code" })?.value, !code.isEmpty,
              isValidHost(host)
        else { throw PairingError.invalidLink }
        return (host, code)
    }

    /// host:port only — reject anything that could smuggle a path,
    /// userinfo, or query into the https URL built from it.
    nonisolated static func isValidHost(_ host: String) -> Bool {
        !host.isEmpty
            && !host.contains(where: { "/@?# \\".contains($0) })
            && URL(string: "https://\(host)")?.host() != nil
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

    /// UI entry point: parse a scanned/opened link and stage it for user
    /// confirmation. Pairing repoints the app and drops existing credentials,
    /// so a bare deep-link tap must never trigger it directly.
    func handle(_ url: URL) async {
        error = nil
        do {
            let p = try Self.parse(url)
            pending = PendingPair(host: p.host, code: p.code)
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
            try await pair(host: p.host, code: p.code)
        } catch PairingError.invalidLink {
            error = "Not an evan-proxy pairing code"
        } catch PairingError.rejected {
            error = "Code expired or already used — generate a new QR"
        } catch {
            self.error = "Connection failed — check network"
        }
    }

    func cancelPending() { pending = nil }

    /// Manual fallback for when the camera is unavailable or declined: stage a
    /// typed host + code for the same user confirmation as a scanned link.
    /// Forgives pasted extras (whitespace, an `https://` prefix, a trailing `/`).
    func handleManual(host rawHost: String, code rawCode: String) {
        error = nil
        var host = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.lowercased().hasPrefix("https://") { host = String(host.dropFirst(8)) }
        if host.hasSuffix("/") { host = String(host.dropLast()) }
        let code = rawCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isValidHost(host), !code.isEmpty else {
            error = "Invalid server address or code"
            return
        }
        pending = PendingPair(host: host, code: code)
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
