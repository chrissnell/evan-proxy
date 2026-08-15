import SwiftUI

struct SettingsView: View {
    let auth: AuthStore
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
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
                        Text("Evan Proxy v\(appVersion)")
                            .font(Typography.mono(14, weight: .bold))
                            .foregroundStyle(Palette.fg)

                        Text("© 2026 Chris Snell")
                            .font(Typography.mono(12))
                            .foregroundStyle(Palette.fgMuted)

                        VStack(spacing: 4) {
                            Text("If you want to run your own filtering proxy, you can download the evan-proxy server software for free at")
                                .font(Typography.mono(12))
                                .foregroundStyle(Palette.fgMuted)
                                .multilineTextAlignment(.center)
                                .fixedSize(horizontal: false, vertical: true)

                            Link("https://github.com/chrissnell/evan-proxy",
                                 destination: URL(string: "https://github.com/chrissnell/evan-proxy")!)
                                .font(Typography.mono(12))
                                .foregroundStyle(Palette.accent)
                        }

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
        }.background(Palette.bg).navigationTitle("Settings")
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }
}
