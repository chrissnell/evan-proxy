import Foundation
import Observation

@Observable @MainActor
final class LoginModel {
    var username = ""; var password = ""; var error: String?; var busy = false
    let auth: AuthStore
    init(auth: AuthStore) { self.auth = auth }

    func submit() async {
        error = nil; busy = true; defer { busy = false }
        do { try await auth.login(username: username, password: password) }
        catch { self.error = "invalid credentials" }
    }
}
