import Foundation
import Observation

enum AuthError: Error { case invalidCredentials, noStoredCredentials, notConfigured }

@Observable
@MainActor
final class AuthStore {
    private let keychain: Keychain
    private(set) var isAuthenticated = false
    var loginFn: (_ username: String, _ password: String) async throws -> Void = { _, _ in
        throw AuthError.notConfigured
    }
    init(keychain: Keychain = Keychain(service: "com.evanproxy.credentials")) {
        self.keychain = keychain
    }
    var hasStoredCredentials: Bool {
        (try? keychain.get("username")) != nil && (try? keychain.get("password")) != nil
    }

    // MARK: Password login (legacy path for existing installs)

    func login(username: String, password: String) async throws {
        try await loginFn(username, password)
        try keychain.set(username, for: "username")
        try keychain.set(password, for: "password")
        isAuthenticated = true
    }
    func reauthenticate() async throws {
        guard let u = try keychain.get("username"), let p = try keychain.get("password") else {
            throw AuthError.noStoredCredentials
        }
        try await loginFn(u, p)
        isAuthenticated = true
    }

    // MARK: QR pairing (device bearer token; no password on the phone)

    var hasDeviceToken: Bool { currentDeviceToken() != nil }

    /// Keychain read is safe off the main actor; used by the bearer middleware.
    nonisolated func currentDeviceToken() -> String? {
        try? keychain.get("deviceToken")
    }

    /// Store the paired token and drop any stored password — the paired path
    /// never keeps the admin credential on the device.
    func storePairing(token: String) throws {
        try keychain.set(token, for: "deviceToken")
        try? keychain.remove("username")
        try? keychain.remove("password")
        isAuthenticated = true
    }

    /// A revoked token can't be refreshed — clear it so the UI returns to pairing.
    func unpair() {
        try? keychain.remove("deviceToken")
        isAuthenticated = false
    }

    func logout() {
        try? keychain.remove("username")
        try? keychain.remove("password")
        try? keychain.remove("deviceToken")
        isAuthenticated = false
    }
}
