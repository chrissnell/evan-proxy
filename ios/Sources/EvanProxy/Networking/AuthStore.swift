import Foundation
import Observation

enum AuthError: Error { case notConfigured }

/// Token-only auth: the app authenticates exclusively with a QR-paired device
/// bearer token — the admin password never lives on the phone.
@Observable
@MainActor
final class AuthStore {
    private let keychain: Keychain
    private(set) var isAuthenticated = false

    init(keychain: Keychain = Keychain(service: "com.evanproxy.credentials")) {
        self.keychain = keychain
        // Migration: scrub the password credential stored by pre-pairing builds.
        try? keychain.remove("username")
        try? keychain.remove("password")
    }

    var hasDeviceToken: Bool { currentDeviceToken() != nil }

    /// Keychain read is safe off the main actor; used by the bearer middleware.
    nonisolated func currentDeviceToken() -> String? {
        try? keychain.get("deviceToken")
    }

    func storePairing(token: String) throws {
        try keychain.set(token, for: "deviceToken")
        isAuthenticated = true
    }

    /// On launch a stored token is trusted until the server says otherwise —
    /// a revoked one 401s on first use and drops back to pairing.
    func resumePairedSession() {
        if hasDeviceToken { isAuthenticated = true }
    }

    /// A revoked token can't be refreshed — clear it so the UI returns to pairing.
    func unpair() {
        try? keychain.remove("deviceToken")
        isAuthenticated = false
    }
}
