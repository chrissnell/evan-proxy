import SwiftUI

struct LogsView: View {
    @State var model: LogsModel
    private static let timeFmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f
    }()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                SectionHeader(title: "log tail · live")
                ForEach(Array(model.lines.enumerated()), id: \.offset) { _, e in
                    Text(format(e)).font(Typography.mono(11)).foregroundStyle(color(e))
                }
            }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Palette.bg).task { model.start() }.onDisappear { model.stop() }
    }
    private func color(_ e: Components.Schemas.LogEntry) -> Color {
        if e.event == "dns-block" || e.event == "dns-err" { return Palette.danger }
        if e.status >= 400 { return Palette.warn }
        return Palette.accent
    }
    private func format(_ e: Components.Schemas.LogEntry) -> String {
        "\(Self.timeFmt.string(from: e.ts))  \(e.user ?? "-")  \(e.event ?? "-")  \(e.host ?? "")  \(e.status)"
    }
}
