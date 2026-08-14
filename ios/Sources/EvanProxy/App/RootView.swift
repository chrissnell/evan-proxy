import SwiftUI

public struct RootView: View {
    @State private var auth: AuthStore
    @State private var pairing: PairingModel
    @State private var client: Client?
    // Mirrors ServerConfig's UserDefaults key so the gate re-renders on save.
    @AppStorage("evanproxy.baseURL") private var baseURLString: String?

    public init() {
        Typography.registerFonts()
        let auth = AuthStore()
        _auth = State(initialValue: auth)
        _pairing = State(initialValue: PairingModel(auth: auth))
    }

    public var body: some View {
        Group {
            if !auth.isAuthenticated {
                PairingView(pairing: pairing)
            } else if let client {
                MainTabs(client: client, auth: auth)
            } else { Color.clear.onAppear(perform: build) }
        }
        .task {
            build()
            auth.resumePairedSession()
        }
        .onChange(of: baseURLString) { build() }
        // `evanproxy://pair` deep link — works from the stock Camera app too.
        .onOpenURL { url in Task { await pairing.handle(url) } }
        // Pairing repoints the app and wipes the stored login, so an untrusted
        // link must never do it without a confirmation that names the host.
        .alert("pair with \(pairing.pending?.host ?? "server")?",
               isPresented: Binding(get: { pairing.pending != nil },
                                    set: { if !$0 { pairing.cancelPending() } }),
               presenting: pairing.pending) { p in
            Button("cancel", role: .cancel) {}
            Button("pair") { Task { await pairing.confirm(p) } }
        } message: { p in
            Text("this points the app at \(p.host) and replaces the current server and pairing on this device")
        }
    }
    private func build() { client = try? APIClientFactory.make(auth: auth) }
}

struct MainTabs: View {
    let client: Client
    let auth: AuthStore
    @State private var users: UsersModel

    init(client: Client, auth: AuthStore) {
        self.client = client
        self.auth = auth
        _users = State(initialValue: UsersModel(api: LiveUsersAPI(client: client)))
    }

    var body: some View {
        TabView {
            DashboardView(model: .init(api: LiveStatsAPI(client: client)))
                .tabItem { Label("dashboard", systemImage: "chart.bar.fill") }
            UsersView(model: users,
                      makeDetail: { UserDetailView(user: $0, api: LiveUsersAPI(client: client),
                                                   onChange: { await users.load() }) },
                      makeSchedule: { ScheduleEditorView(user: $0, api: LiveUsersAPI(client: client),
                                                         onChange: { await users.load() }) })
                .tabItem { Label("users", systemImage: "person.2.fill") }
            LogsView(model: .init(stream: LogStream(
                baseURL: ServerConfig.baseURL!,
                // A 401 means the token was revoked — unpair back to pairing.
                onAuthFailure: { await auth.unpair() },
                bearer: { auth.currentDeviceToken() })))
                .tabItem { Label("logs", systemImage: "terminal.fill") }
            NavigationStack { SettingsView(auth: auth) }
                .tabItem { Label("settings", systemImage: "gearshape.fill") }
        }
        .tint(Palette.accent)
    }
}
