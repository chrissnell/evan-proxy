import SwiftUI

struct SettingsView: View {
    let auth: AuthStore
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "server")
                Box {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("paired with").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                        // The URL comes from the pairing QR; re-pair to change it.
                        Text(ServerConfig.baseURL?.absoluteString ?? "—")
                            .font(Typography.mono(14)).foregroundStyle(Palette.fg)
                    }
                }
                SectionHeader(title: "device")
                Box {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("unpairing removes this device's token —\nscan a new QR to reconnect")
                            .font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                        PillButton(title: "unpair", color: Palette.danger) {
                            auth.unpair()
                        }
                    }
                }
            }.padding(12)
        }.background(Palette.bg).navigationTitle("settings")
    }
}
