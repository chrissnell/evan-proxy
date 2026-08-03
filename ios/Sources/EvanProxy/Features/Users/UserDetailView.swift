import SwiftUI

struct UserDetailView: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingDelete = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "access")
                Box {
                    Toggle(isOn: .constant(user.enabled)) { Text("proxy enabled").font(Typography.mono(14)) }
                        .tint(Palette.accent)
                }
                SectionHeader(title: "configuration")
                Box {
                    VStack(spacing: 0) {
                        NavigationLink { PortEditor(user: user, api: api, onChange: onChange) } label: { row("port", "\(user.port)") }
                        Divider().overlay(Palette.borderSubtle)
                        NavigationLink { DNSEditor(user: user, api: api, onChange: onChange) } label: { row("dns", user.dns_server.isEmpty ? "default" : user.dns_server) }
                        Divider().overlay(Palette.borderSubtle)
                        NavigationLink { PasswordEditor(user: user, api: api) } label: { row("password", "••••••••") }
                    }
                }
                PillButton(title: confirmingDelete ? "confirm delete" : "delete user", color: Palette.danger) {
                    if confirmingDelete { Task { try? await api.deleteUser(user.username); await onChange(); dismiss() } }
                    else { confirmingDelete = true }
                }.padding(.top, 8)
            }.padding(12)
        }
        .background(Palette.bg).navigationTitle(user.username)
    }
    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(Palette.fg); Spacer()
                 Text(v).foregroundStyle(Palette.fgMuted); Image(systemName: "chevron.right").foregroundStyle(Palette.fgDim) }
            .font(Typography.mono(14)).padding(.vertical, 10)
    }
}

struct PortEditor: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var port = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "port")
            Box {
                TextField("", text: $port).keyboardType(.numberPad).font(Typography.mono(14))
                    .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
            }
            PillButton(title: "save", color: Palette.accent, filled: true) {
                guard let p = Int(port) else { return }
                Task { try? await api.setPort(user.username, p); await onChange(); dismiss() }
            }
        }
        .padding(12).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg).navigationTitle("port · \(user.username)")
        .onAppear { port = String(user.port) }
    }
}

struct DNSEditor: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var server = ""
    @State private var proto = "plain"
    @State private var testResult: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "dns override")
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    Text("server (empty = default)").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("", text: $server).textInputAutocapitalization(.never)
                        .autocorrectionDisabled().font(Typography.mono(14))
                        .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Picker("protocol", selection: $proto) {
                        ForEach(["plain", "tls", "https"], id: \.self) { Text($0).font(Typography.mono(12)) }
                    }.pickerStyle(.segmented)
                    if let t = testResult {
                        Text(t).font(Typography.mono(12))
                            .foregroundStyle(t == "ok" ? Palette.accent : Palette.danger)
                    }
                }
            }
            HStack(spacing: 6) {
                PillButton(title: "test") {
                    Task { testResult = ((try? await api.testDNS(server: server, proto: proto)) == true) ? "ok" : "failed" }
                }
                PillButton(title: "save", color: Palette.accent, filled: true) {
                    Task {
                        try? await api.setDNS(user.username, server: server, proto: server.isEmpty ? "" : proto)
                        await onChange(); dismiss()
                    }
                }
            }
        }
        .padding(12).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg).navigationTitle("dns · \(user.username)")
        .onAppear { server = user.dns_server; proto = user.dns_protocol == ._empty ? "plain" : user.dns_protocol.rawValue }
    }
}

struct PasswordEditor: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "new password")
            Box {
                SecureField("", text: $password).font(Typography.mono(14))
                    .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
            }
            PillButton(title: "save", color: Palette.accent, filled: true) {
                guard !password.isEmpty else { return }
                Task { try? await api.changePassword(user.username, password); dismiss() }
            }
        }
        .padding(12).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg).navigationTitle("password · \(user.username)")
    }
}
