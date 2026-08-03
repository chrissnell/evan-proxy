import SwiftUI

struct UsersView: View {
    @State var model: UsersModel
    let makeDetail: (Components.Schemas.UserInfo) -> UserDetailView
    let makeSchedule: (Components.Schemas.UserInfo) -> ScheduleEditorView
    @State private var detailUser: Components.Schemas.UserInfo?
    @State private var scheduleUser: Components.Schemas.UserInfo?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 10) {
                    SectionHeader(title: "proxy users")
                    ForEach(model.users, id: \.username) { u in
                        UserCard(user: u,
                            onToggle: { on in Task { await model.setEnabled(u.username, on) } },
                            onSchedule: { scheduleUser = u },
                            onEdit: { detailUser = u },
                            onOverride: { detailUser = u })
                    }
                    PillButton(title: "+ add user", color: Palette.accent) { detailUser = nil /* present add sheet */ }
                }.padding(12)
            }
            .background(Palette.bg)
            .navigationDestination(item: $detailUser) { makeDetail($0) }
            .navigationDestination(item: $scheduleUser) { makeSchedule($0) }
            .task { await model.load() }
            .refreshable { await model.load() }
        }
    }
}
