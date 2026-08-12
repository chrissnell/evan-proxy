import SwiftUI

struct DashboardView: View {
    @State var model: DashboardModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("evan-proxy")
                    .font(Typography.mono(22, weight: .bold))
                    .foregroundStyle(Palette.fg)
                SectionHeader(title: "bandwidth · 1h")
                Box { TrafficChart(buckets: model.buckets, value: { Int($0.bw) }) }
                SectionHeader(title: "requests · 1h")
                Box { TrafficChart(buckets: model.buckets, value: { Int($0.reqs) }) }
                SectionHeader(title: "top sites · 24h")
                Box { hostList(model.topSites) }
                SectionHeader(title: "dns blocked · 24h")
                Box { hostList(model.topBlocked, color: Palette.danger) }
            }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Palette.bg)
        .task { model.start() }
        .onDisappear { model.stop() }
    }

    private func hostList(_ hosts: [Components.Schemas.HostCount], color: Color = Palette.fg) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if hosts.isEmpty {
                Text("no data").font(Typography.mono(12)).foregroundStyle(Palette.fgDim)
            }
            ForEach(Array(hosts.enumerated()), id: \.offset) { _, h in
                HStack {
                    Text(h.host).font(Typography.mono(12)).foregroundStyle(color)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text("\(h.count)").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                }
            }
        }
    }
}
