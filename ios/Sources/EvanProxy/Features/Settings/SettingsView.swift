import SwiftUI

struct SettingsView: View {
    let auth: AuthStore
    var client: Client?
    @State private var serverVersion: String?
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                PageTitle(title: "SETTINGS")
                SectionHeader(title: "server")
                Box {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Paired with").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                        // The URL comes from the pairing QR; re-pair to change it.
                        Text(ServerConfig.baseURL?.absoluteString ?? "—")
                            .font(Typography.mono(14)).foregroundStyle(Palette.fg)
                    }
                }
                SectionHeader(title: "device")
                Box {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Unpairing removes the token from this device only —\nrevoke it in the admin \"Devices\" panel too.\nScan a new QR to reconnect")
                            .font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                        PillButton(title: "Unpair", color: Palette.danger) {
                            auth.unpair()
                        }
                    }
                }
                SectionHeader(title: "about")
                Box {
                    VStack(alignment: .center, spacing: 12) {
                        Text("evan-proxy")
                            .font(Typography.mono(14, weight: .bold))
                            .foregroundStyle(Palette.fg)

                        VStack(spacing: 2) {
                            Text("App Version: \(vPrefixed(appVersion))")
                            Text("Server Version: \(serverVersion.map(vPrefixed) ?? "—")")
                        }
                        .font(Typography.mono(12))
                        .foregroundStyle(Palette.fgMuted)

                        Text("© 2026 Chris Snell")
                            .font(Typography.mono(12))
                            .foregroundStyle(Palette.fgMuted)

                        Spacer()
                            .frame(height: 8)

                        Text("\"And behold, I tell you these things that ye may learn wisdom; that when ye are in the service of your fellow beings ye are only in the service of your God.\"")
                            .font(Typography.mono(12))
                            .foregroundStyle(Palette.fgMuted)
                            .multilineTextAlignment(.center)
                            .italic()

                        Link("Mosiah 2:17",
                             destination: URL(string: "https://www.churchofjesuschrist.org/study/scriptures/bofm/mosiah/2?lang=eng&id=p16#p16")!)
                            .font(Typography.mono(12))
                            .foregroundStyle(Palette.accent)
                    }
                    .frame(maxWidth: .infinity)
                }
            }.padding(12)
        }.background(Palette.bg)
        .task {
            guard let client else { return }
            serverVersion = try? await client.getVersion().ok.body.json.version
        }
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }

    /// "1.2.3" → "v1.2.3", but leave non-numeric versions like "dev" alone.
    private func vPrefixed(_ s: String) -> String {
        s.first?.isNumber == true ? "v\(s)" : s
    }
}
