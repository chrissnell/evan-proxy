import SwiftUI

struct LogsView: View {
    @State var model: LogsModel
    private static let timeFmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f
    }()

    var body: some View {
        ScrollView {
            ScrollViewReader { proxy in
                VStack(alignment: .leading, spacing: 2) {
                    SectionHeader(title: "log tail · live")
                    ForEach(Array(model.lines.enumerated()), id: \.offset) { _, e in
                        row(e)
                    }
                    Color.clear.frame(height: 0).id(bottomID)
                }
                .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                .onChange(of: model.lines.count) {
                    withAnimation(.linear(duration: 0.1)) { proxy.scrollTo(bottomID, anchor: .bottom) }
                }
            }
        }
        .background(Palette.bg).task { model.start() }.onDisappear { model.stop() }
    }

    private let bottomID = "log-bottom"

    // Fixed-width monospace columns keep the tail vertically aligned like the web UI.
    private func row(_ e: Components.Schemas.LogEntry) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(Self.timeFmt.string(from: e.ts))
                .frame(width: 56, alignment: .leading)
            Text(e.user ?? "-")
                .frame(width: 62, alignment: .leading).lineLimit(1).truncationMode(.tail)
            Text(e.event ?? "-")
                .frame(width: 54, alignment: .leading).lineLimit(1).truncationMode(.tail)
            Text(e.host ?? "")
                .frame(maxWidth: .infinity, alignment: .leading).lineLimit(1).truncationMode(.middle)
            Text("\(e.status)")
                .frame(width: 30, alignment: .trailing)
        }
        .font(Typography.mono(11)).foregroundStyle(color(e))
    }

    private func color(_ e: Components.Schemas.LogEntry) -> Color {
        if e.event == "dns-block" || e.event == "dns-err" { return Palette.danger }
        if e.status >= 400 { return Palette.warn }
        return Palette.accent
    }
}
