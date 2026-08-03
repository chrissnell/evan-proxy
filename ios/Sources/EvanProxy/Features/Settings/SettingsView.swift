import SwiftUI

struct SettingsView: View {
    let auth: AuthStore
    @State private var urlString = ServerConfig.baseURL?.absoluteString ?? ""
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "server")
                Box {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("base url").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                        TextField("https://proxy.example.com", text: $urlString)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .keyboardType(.URL)
                            .font(Typography.mono(14)).padding(8)
                            .overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                        PillButton(title: "save", color: Palette.accent) {
                            ServerConfig.baseURL = URL(string: urlString)
                        }
                    }
                }
                PillButton(title: "logout", color: Palette.danger) { auth.logout() }
            }.padding(12)
        }.background(Palette.bg).navigationTitle("settings")
    }
}
