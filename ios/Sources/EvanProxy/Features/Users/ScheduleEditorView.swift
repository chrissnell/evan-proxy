import SwiftUI

struct ScheduleEditorView: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var schedule: [String: [Components.Schemas.DowntimeWindow]] = [:]
    @State private var editing: EditRef?

    private let dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "weekly schedule")
                ForEach(0..<7, id: \.self) { d in dayRow(d) }
                HStack {
                    PillButton(title: "copy Sun → all") { copySundayToAll() }
                    PillButton(title: "save", color: Palette.accent, filled: true) {
                        Task { try? await api.setDowntime(user.username, cleaned()); await onChange(); dismiss() }
                    }
                }.padding(.top, 8)
            }.padding(12)
        }
        .background(Palette.bg).navigationTitle("downtime · \(user.username)")
        .onAppear { schedule = user.downtime_schedule?.additionalProperties ?? [:] }
        .sheet(item: $editing) { ref in
            TimeWheelSheet(window: binding(for: ref)) {
                schedule[String(ref.day)]?.remove(at: ref.index)
                editing = nil
            }
        }
    }

    private func dayRow(_ d: Int) -> some View {
        Box {
            VStack(alignment: .leading, spacing: 6) {
                Text(dayNames[d]).font(Typography.mono(13, weight: .bold)).foregroundStyle(Palette.fg)
                HStack(spacing: 6) {
                    let wins = schedule[String(d)] ?? []
                    ForEach(wins.indices, id: \.self) { i in
                        Button { editing = EditRef(day: d, index: i) } label: {
                            StatusChip(text: "\(wins[i].start)–\(wins[i].end)", color: Palette.warn)
                        }
                    }
                    Button { addWindow(day: d) } label: {
                        Text("+ add").font(Typography.mono(12)).foregroundStyle(Palette.accent)
                    }
                }
            }
        }
    }

    private func addWindow(day: Int) {
        var wins = schedule[String(day)] ?? []
        wins.append(.init(start: "22:00", end: "06:00"))
        schedule[String(day)] = wins
        editing = EditRef(day: day, index: wins.count - 1)
    }

    private func binding(for ref: EditRef) -> Binding<Components.Schemas.DowntimeWindow> {
        Binding(
            get: {
                let wins = schedule[String(ref.day)] ?? []
                return wins.indices.contains(ref.index) ? wins[ref.index] : .init(start: "22:00", end: "06:00")
            },
            set: { w in
                var wins = schedule[String(ref.day)] ?? []
                guard wins.indices.contains(ref.index) else { return }
                wins[ref.index] = w
                schedule[String(ref.day)] = wins
            }
        )
    }

    private func cleaned() -> [String: [Components.Schemas.DowntimeWindow]] {
        schedule.filter { !$0.value.isEmpty }
    }

    private func copySundayToAll() {
        let sun = schedule["0"] ?? []
        for d in 1...6 { schedule[String(d)] = sun }
    }
}

struct EditRef: Identifiable { let day: Int; let index: Int; var id: String { "\(day)-\(index)" } }

struct TimeWheelSheet: View {
    @Binding var window: Components.Schemas.DowntimeWindow
    let onRemove: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 12) {
            SectionHeader(title: "downtime window")
            HStack {
                picker("start", $window.start)
                picker("end", $window.end)
            }
            HStack(spacing: 6) {
                PillButton(title: "remove", color: Palette.danger) { onRemove() }
                PillButton(title: "done", color: Palette.accent, filled: true) { dismiss() }
            }
        }
        .padding(16)
        .presentationDetents([.height(340)])
        .background(Palette.bg)
    }

    private func picker(_ label: String, _ hhmm: Binding<String>) -> some View {
        VStack {
            Text(label).font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
            DatePicker("", selection: dateBinding(hhmm), displayedComponents: .hourAndMinute)
                .datePickerStyle(.wheel).labelsHidden()
        }
    }

    private func dateBinding(_ hhmm: Binding<String>) -> Binding<Date> {
        Binding(
            get: {
                let p = hhmm.wrappedValue.split(separator: ":")
                var c = DateComponents()
                c.hour = Int(p.first ?? "0") ?? 0
                c.minute = p.count > 1 ? (Int(p[1]) ?? 0) : 0
                return Calendar.current.date(from: c) ?? Date()
            },
            set: {
                let c = Calendar.current.dateComponents([.hour, .minute], from: $0)
                hhmm.wrappedValue = String(format: "%02d:%02d", c.hour ?? 0, c.minute ?? 0)
            }
        )
    }
}
