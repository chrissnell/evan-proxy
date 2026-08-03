import Foundation
import Observation

@Observable @MainActor
final class LogsModel {
    var lines: [Components.Schemas.LogEntry] = []
    private var task: Task<Void, Never>?
    let stream: LogStream
    init(stream: LogStream) { self.stream = stream }
    func start() {
        task = Task {
            do { for try await e in stream.connect() {
                lines.append(e); if lines.count > 200 { lines.removeFirst(lines.count - 200) }
            } } catch {}
        }
    }
    func stop() { task?.cancel() }
}
