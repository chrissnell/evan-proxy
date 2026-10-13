import SwiftUI

struct UsersView: View {
    @State var model: UsersModel
    let makeDetail: (Components.Schemas.UserInfo) -> UserDetailView
    let makeSchedule: (Components.Schemas.UserInfo) -> ScheduleEditorView
    @State private var detailUser: Components.Schemas.UserInfo?
    @State private var scheduleUser: Components.Schemas.UserInfo?
    @State private var overrideUser: Components.Schemas.UserInfo?
    @State private var downtimeUsername: String?
    @State private var showingAdd = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 10) {
                    PageTitle(title: "PROXY USERS")
                    if let e = model.error {
                        Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                    }
                    ForEach(model.users, id: \.username) { u in
                        UserCard(user: u,
                            onToggle: { on in Task { await model.setEnabled(u.username, on) } },
                            onSchedule: { scheduleUser = u },
                            onEdit: { detailUser = u },
                            onOverride: { overrideUser = u },
                            onDowntime: { downtimeUsername = u.username },
                            onEndDowntime: { Task { await model.setDowntimeNow(u.username, minutes: 0) } })
                    }
                    PillButton(title: "+ Add User", color: Palette.accent) { showingAdd = true }
                }.padding(12)
            }
            .background(Palette.bg)
            .navigationDestination(item: $detailUser) { makeDetail($0) }
            .navigationDestination(item: $scheduleUser) { makeSchedule($0) }
            .confirmationDialog("Downtime override", isPresented: overridePresented,
                                titleVisibility: .visible, presenting: overrideUser) { u in
                if case .override = UserStatus.state(for: u) {
                    Button("Cancel Override", role: .destructive) {
                        Task { await model.setOverride(u.username, minutes: 0) }
                    }
                } else {
                    Button("30 minutes") { Task { await model.setOverride(u.username, minutes: 30) } }
                    Button("1 hour") { Task { await model.setOverride(u.username, minutes: 60) } }
                    Button("2 hours") { Task { await model.setOverride(u.username, minutes: 120) } }
                }
            }
            .sheet(isPresented: downtimePresented) {
                if let username = downtimeUsername {
                    DowntimeSheet(username: username) { minutes in
                        Task { await model.setDowntimeNow(username, minutes: minutes) }
                    }
                }
            }
            .sheet(isPresented: $showingAdd) {
                AddUserSheet { u, p in await model.createUser(u, p) }
            }
            .task { await model.load() }
            .refreshable { await model.load() }
        }
    }

    private var overridePresented: Binding<Bool> {
        Binding(get: { overrideUser != nil }, set: { if !$0 { overrideUser = nil } })
    }
    private var downtimePresented: Binding<Bool> {
        Binding(get: { downtimeUsername != nil }, set: { if !$0 { downtimeUsername = nil } })
    }
}

/// One duration choice in the ad-hoc downtime picker.
private struct DowntimeChoice: Identifiable {
    let minutes: Int
    let label: String
    var id: Int { minutes }
}

/// Ad-hoc downtime duration picker. The 4x2 grid of choices mirrors the admin
/// UI's picker so both front-ends offer the same durations in the same order.
struct DowntimeSheet: View {
    let username: String
    let onPick: (Int) -> Void
    @Environment(\.dismiss) private var dismiss

    private let choices = [
        DowntimeChoice(minutes: 15, label: "15m"),
        DowntimeChoice(minutes: 30, label: "30m"),
        DowntimeChoice(minutes: 60, label: "1h"),
        DowntimeChoice(minutes: 180, label: "3h"),
        DowntimeChoice(minutes: 360, label: "6h"),
        DowntimeChoice(minutes: 720, label: "12h"),
        DowntimeChoice(minutes: 1440, label: "1d"),
        DowntimeChoice(minutes: 10080, label: "1w")
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "downtime for")
            Box {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 4),
                          spacing: 6) {
                    ForEach(choices) { choice in
                        PillButton(title: choice.label, color: Palette.warn) {
                            onPick(choice.minutes)
                            dismiss()
                        }
                    }
                }
            }
            Text("Blocks \(username) right away. Access comes back on its own when the timer runs out.")
                .font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
            PillButton(title: "Cancel") { dismiss() }
        }
        .padding(16).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg)
        .presentationDetents([.height(300)])
    }
}

struct AddUserSheet: View {
    /// Returns true on success; sheet dismisses itself then.
    let onCreate: (String, String) async -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "add user")
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Username").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("", text: $username)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(Typography.mono(14)).padding(8)
                        .overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Text("Password").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    SecureField("", text: $password)
                        .font(Typography.mono(14)).padding(8)
                        .overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    if let e = error {
                        Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                    }
                }
            }
            PillButton(title: busy ? "Creating…" : "Create", color: Palette.accent, filled: true) {
                guard !username.isEmpty, !password.isEmpty, !busy else { return }
                busy = true
                Task {
                    defer { busy = false }
                    if await onCreate(username, password) { dismiss() }
                    else { error = "Failed to create user (name taken?)" }
                }
            }
        }
        .padding(16).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg)
        .presentationDetents([.height(320)])
    }
}
