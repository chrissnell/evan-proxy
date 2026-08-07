import SwiftUI

struct UserCard: View {
    let user: Components.Schemas.UserInfo
    let onToggle: (Bool) -> Void
    let onSchedule: () -> Void
    let onEdit: () -> Void
    let onOverride: () -> Void

    var body: some View {
        Box {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(user.username).font(Typography.mono(15, weight: .bold)).foregroundStyle(Palette.fg)
                    Spacer()
                    Toggle("", isOn: Binding(get: { user.enabled }, set: { onToggle($0) }))
                        .labelsHidden().tint(Palette.accent)
                }
                chip
                Text(meta).font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                HStack(spacing: 6) {
                    if case .downtime = state { PillButton(title: "override", color: Palette.purple, action: onOverride) }
                    if case .override = state { PillButton(title: "cancel override", color: Palette.purple, action: onOverride) }
                    PillButton(title: "schedule", action: onSchedule)
                    PillButton(title: "edit", action: onEdit)
                }
            }
        }
    }

    private var state: DisplayState { UserStatus.state(for: user) }
    private var chip: some View {
        switch state {
        case .enabled:  return StatusChip(text: "enabled", color: Palette.accent)
        case .disabled: return StatusChip(text: "disabled", color: Palette.danger)
        case .downtime: return StatusChip(text: "downtime", color: Palette.warn)
        case .override(let until):
            let m = max(0, Int(until.timeIntervalSinceNow / 60))
            return StatusChip(text: "override · \(m)m left", color: Palette.purple)
        }
    }
    private var meta: String {
        let dns = user.dns_server.isEmpty ? "default" : "\(user.dns_protocol.rawValue)://\(user.dns_server)"
        return "port \(user.port) · dns \(dns)"
    }
}
