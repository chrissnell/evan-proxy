import CryptoKit
import Foundation
import Security

/// Pure trust-on-first-use decision logic, kept free of Security-framework
/// types so it can be unit-tested. Fingerprints are SHA-256 of the leaf
/// certificate's DER bytes, lowercase hex.
enum TrustEvaluator {
    enum Verdict: Equatable {
        case allowSystemTrusted
        case allowPinned
        case allowAndPin
        case reject
    }

    /// `mayPin` is true only while a user-confirmed pairing for this host is
    /// in flight — the sole moment an unknown self-signed cert may be adopted.
    static func evaluate(systemTrusted: Bool, presented: String, pinned: String?, mayPin: Bool) -> Verdict {
        if systemTrusted { return .allowSystemTrusted }
        if let pinned { return presented == pinned ? .allowPinned : .reject }
        return mayPin ? .allowAndPin : .reject
    }
}

/// Pinned certificate fingerprints, one per host. Not secret — the pin
/// protects integrity (which cert we accept), not confidentiality.
enum CertPinStore {
    private static func key(_ host: String) -> String { "evanproxy.pinnedCert.\(host)" }

    static func fingerprint(for host: String) -> String? {
        UserDefaults.standard.string(forKey: key(host))
    }
    static func pin(_ fingerprint: String, for host: String) {
        UserDefaults.standard.set(fingerprint, forKey: key(host))
    }
    static func clear(host: String) {
        UserDefaults.standard.removeObject(forKey: key(host))
    }
}

/// URLSession delegate that accepts self-signed server certificates via TOFU:
/// system-trusted certs pass as usual; an untrusted cert is adopted (pinned)
/// only during a user-confirmed pairing, and afterwards only that exact
/// certificate is accepted for the host. Serves every connection in the app —
/// the generated API client, the pairing call, and the SSE log stream all
/// share APIClientFactory.session.
final class TOFUSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var pairingHost: String?

    /// Open the TOFU window for a host the user just confirmed pairing with.
    /// Any previous pin is dropped so a reinstalled server can present a new
    /// certificate — re-pairing is the recovery path for cert rotation.
    func beginPairing(host: String) {
        CertPinStore.clear(host: host)
        lock.lock()
        pairingHost = host
        lock.unlock()
    }

    func endPairing() {
        lock.lock()
        pairingHost = nil
        lock.unlock()
    }

    private func mayPin(_ host: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return pairingHost == host
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = space.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let systemTrusted = SecTrustEvaluateWithError(trust, nil)
        guard let fingerprint = Self.leafFingerprint(trust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        switch TrustEvaluator.evaluate(systemTrusted: systemTrusted,
                                       presented: fingerprint,
                                       pinned: CertPinStore.fingerprint(for: space.host),
                                       mayPin: mayPin(space.host)) {
        case .allowSystemTrusted:
            completionHandler(.performDefaultHandling, nil)
        case .allowPinned:
            completionHandler(.useCredential, URLCredential(trust: trust))
        case .allowAndPin:
            CertPinStore.pin(fingerprint, for: space.host)
            completionHandler(.useCredential, URLCredential(trust: trust))
        case .reject:
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    static func leafFingerprint(_ trust: SecTrust) -> String? {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else { return nil }
        let der = SecCertificateCopyData(leaf) as Data
        return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }
}
