import SwiftUI

public struct RootView: View {
    @State private var auth = AuthStore()
    @State private var client: Client?
    // Mirrors ServerConfig's UserDefaults key so the gate re-renders on save.
    @AppStorage("evanproxy.baseURL") private var baseURLString: String?

    public init() { Typography.registerFonts() }

    public var body: some View {
        Group {
            if baseURLString == nil {
                NavigationStack { SettingsView(auth: auth) }
            } else if !auth.isAuthenticated {
                LoginView(model: LoginModel(auth: auth))
            } else if let client {
                MainTabs(client: client, auth: auth)
            } else { Color.clear.onAppear(perform: build) }
        }
        .task { await trySilentLogin() }
        .onChange(of: baseURLString) { build() }
    }
    private func build() { client = try? APIClientFactory.make(auth: auth) }
    private func trySilentLogin() async {
        build()
        if auth.hasStoredCredentials { try? await auth.reauthenticate() }  // "log in once"
    }
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
            LogsView(model: .init(stream: LogStream(baseURL: ServerConfig.baseURL!,
                                                    reauth: { try? await auth.reauthenticate() })))
                .tabItem { Label("logs", systemImage: "terminal.fill") }
            NavigationStack { SettingsView(auth: auth, client: client) }
                .tabItem { Label("settings", systemImage: "gearshape.fill") }
        }
        .tint(Palette.accent)
    }
}
