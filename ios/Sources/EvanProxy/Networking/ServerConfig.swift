import Foundation

/// Persisted base URL for the admin server. Stored in UserDefaults (non-secret).
struct ServerConfig {
    private static let key = "evanproxy.baseURL"

    static var baseURL: URL? {
        get { UserDefaults.standard.string(forKey: key).flatMap(URL.init(string:)) }
        set { UserDefaults.standard.set(newValue?.absoluteString, forKey: key) }
    }
}
