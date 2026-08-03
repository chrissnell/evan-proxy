import Foundation

enum SSEParser {
    /// Turn an async sequence of SSE lines into decoded LogEntry values.
    static func entries<S: AsyncSequence & Sendable>(from lines: S) -> AsyncThrowingStream<Components.Schemas.LogEntry, Error>
        where S.Element == String {
        AsyncThrowingStream { cont in
            let task = Task {
                let decoder = JSONDecoder()
                decoder.dateDecodingStrategy = .iso8601   // ts is RFC3339 in the SSE stream
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
    /// Open the SSE endpoint and yield entries until cancelled.
    func connect() -> AsyncThrowingStream<Components.Schemas.LogEntry, Error> {
        AsyncThrowingStream { cont in
            let task = Task {
                do {
                    var req = URLRequest(url: baseURL.appendingPathComponent("api/logs"))
                    req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                    let (bytes, _) = try await APIClientFactory.session.bytes(for: req)
                    for try await entry in SSEParser.entries(from: bytes.lines) { cont.yield(entry) }
                    cont.finish()
                } catch { cont.finish(throwing: error) }
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }
}
