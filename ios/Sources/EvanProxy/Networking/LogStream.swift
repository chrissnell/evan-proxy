import Foundation

enum SSEParser {
    /// Go's time.Time marshals RFC3339 with arbitrary-precision fractional seconds;
    /// Foundation's `.iso8601` strategy rejects fractions, so try both formats then strip.
    static func parseDate(_ s: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = fractional.date(from: s) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let d = plain.date(from: s) { return d }
        let stripped = s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression)
        return plain.date(from: stripped)
    }

    static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { d in
            let c = try d.singleValueContainer()
            let s = try c.decode(String.self)
            guard let date = parseDate(s) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "invalid RFC3339 date: \(s)")
            }
            return date
        }
        return decoder
    }

    /// Turn an async sequence of SSE lines into decoded LogEntry values.
    static func entries<S: AsyncSequence & Sendable>(from lines: S) -> AsyncThrowingStream<Components.Schemas.LogEntry, Error>
        where S.Element == String {
        AsyncThrowingStream { cont in
            let task = Task {
                let decoder = makeDecoder()
                do {
                    for try await line in lines {
                        guard line.hasPrefix("data:") else { continue }
                        let json = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                        if json.isEmpty { continue }
                        if let entry = try? decoder.decode(Components.Schemas.LogEntry.self, from: Data(json.utf8)) {
                            cont.yield(entry)
                        }
                    }
                    cont.finish()
                } catch { cont.finish(throwing: error) }
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }
}

@MainActor
struct LogStream {
    let baseURL: URL
    var onAuthFailure: (@Sendable () async -> Void)?
    /// Device bearer token for QR-paired installs (the SSE request bypasses the
    /// generated client, so the middleware can't add the header for us).
    var bearer: (@Sendable () -> String?)?

    init(baseURL: URL,
         onAuthFailure: (@Sendable () async -> Void)? = nil,
         bearer: (@Sendable () -> String?)? = nil) {
        self.baseURL = baseURL
        self.onAuthFailure = onAuthFailure
        self.bearer = bearer
    }

    /// Open the SSE endpoint and yield entries until cancelled.
    /// Reconnects with backoff on drop; reports a 401 (revoked token) via onAuthFailure.
    func connect() -> AsyncThrowingStream<Components.Schemas.LogEntry, Error> {
        let url = baseURL.appendingPathComponent("api/logs")
        let onAuthFailure = self.onAuthFailure
        let bearer = self.bearer
        return AsyncThrowingStream { cont in
            let task = Task {
                var delay = 1.0
                while !Task.isCancelled {
                    do {
                        var req = URLRequest(url: url)
                        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                        if let tok = bearer?() {
                            req.setValue("Bearer \(tok)", forHTTPHeaderField: "Authorization")
                        }
                        let (bytes, resp) = try await APIClientFactory.session.bytes(for: req)
                        if (resp as? HTTPURLResponse)?.statusCode == 401 {
                            await onAuthFailure?()
                        } else {
                            for try await entry in SSEParser.entries(from: bytes.lines) {
                                delay = 1.0
                                cont.yield(entry)
                            }
                        }
                    } catch is CancellationError {
                        break
                    } catch {
                        // Fall through to backoff and retry.
                    }
                    if Task.isCancelled { break }
                    try? await Task.sleep(for: .seconds(delay))
                    delay = min(delay * 2, 30)
                }
                cont.finish()
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }
}
