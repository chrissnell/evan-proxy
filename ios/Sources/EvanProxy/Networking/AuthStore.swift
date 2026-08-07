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
    func logout() {
        try? keychain.remove("username")
        try? keychain.remove("password")
        isAuthenticated = false
    }
}
