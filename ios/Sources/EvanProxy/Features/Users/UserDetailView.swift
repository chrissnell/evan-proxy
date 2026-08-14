import SwiftUI

struct UserDetailView: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingDelete = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "access")
                Box {
                    HStack {
                        Text("Proxy status").font(Typography.mono(14)).foregroundStyle(Palette.fg)
                        Spacer()
                        StatusChip(text: user.enabled ? "Enabled" : "Disabled",
                                   color: user.enabled ? Palette.accent : Palette.danger)
                    }
                }
                SectionHeader(title: "configuration")
                Box {
                    VStack(spacing: 0) {
                        NavigationLink { PortEditor(user: user, api: api, onChange: onChange) } label: { row("Port", "\(user.port)") }
                        Divider().overlay(Palette.borderSubtle)
                        NavigationLink { DNSEditor(user: user, api: api, onChange: onChange) } label: { row("DNS", user.dns_server.isEmpty ? "Default" : user.dns_server) }
                        Divider().overlay(Palette.borderSubtle)
                        NavigationLink { PasswordEditor(user: user, api: api) } label: { row("Password", "••••••••") }
                    }
                }
                if let e = error {
                    Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                }
                PillButton(title: confirmingDelete ? "Confirm Delete" : "Delete User", color: Palette.danger) {
                    if confirmingDelete {
                        Task {
                            do { try await api.deleteUser(user.username); await onChange(); dismiss() }
                            catch { self.error = "Delete failed"; confirmingDelete = false }
                        }
                    } else { confirmingDelete = true }
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
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "port")
            Box {
                TextField("", text: $port).keyboardType(.numberPad).font(Typography.mono(14))
                    .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
            }
            if let e = error { Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger) }
            PillButton(title: "Save", color: Palette.accent, filled: true) {
                guard let p = Int(port) else { return }
                Task {
                    do { try await api.setPort(user.username, p); await onChange(); dismiss() }
                    catch { self.error = "Save failed (port in use?)" }
                }
            }
        }
        .padding(12).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg).navigationTitle("Port · \(user.username)")
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
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "dns override")
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Server (empty = default)").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("", text: $server).textInputAutocapitalization(.never)
                        .autocorrectionDisabled().font(Typography.mono(14))
                        .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Picker("protocol", selection: $proto) {
                        ForEach(["plain", "tls", "https"], id: \.self) { Text($0).font(Typography.mono(12)) }
                    }.pickerStyle(.segmented)
                    if let t = testResult {
                        Text(t).font(Typography.mono(12))
                            .foregroundStyle(t == "OK" ? Palette.accent : Palette.danger)
                    }
                }
            }
            if let e = error { Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger) }
            HStack(spacing: 6) {
                PillButton(title: "Test") {
                    Task { testResult = ((try? await api.testDNS(server: server, proto: proto)) == true) ? "OK" : "Failed" }
                }
                PillButton(title: "Save", color: Palette.accent, filled: true) {
                    Task {
                        do {
                            try await api.setDNS(user.username, server: server, proto: server.isEmpty ? "" : proto)
                            await onChange(); dismiss()
                        } catch { self.error = "Save failed" }
                    }
                }
            }
        }
        .padding(12).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg).navigationTitle("DNS · \(user.username)")
        .onAppear { server = user.dns_server; proto = user.dns_protocol == ._empty ? "plain" : user.dns_protocol.rawValue }
    }
}

struct PasswordEditor: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "new password")
            Box {
                SecureField("", text: $password).font(Typography.mono(14))
                    .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
            }
            if let e = error { Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger) }
            PillButton(title: "Save", color: Palette.accent, filled: true) {
                guard !password.isEmpty else { return }
                Task {
                    do { try await api.changePassword(user.username, password); dismiss() }
                    catch { self.error = "Save failed" }
                }
            }
        }
        .padding(12).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg).navigationTitle("Password · \(user.username)")
    }
}
