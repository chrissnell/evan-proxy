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
                    if case .downtime = state { PillButton(title: "Override", color: Palette.purple, action: onOverride) }
                    if case .override = state { PillButton(title: "Cancel Override", color: Palette.purple, action: onOverride) }
                    PillButton(title: "Schedule", action: onSchedule)
                    PillButton(title: "Edit", action: onEdit)
                }
            }
        }
    }

    private var state: DisplayState { UserStatus.state(for: user) }
    private var chip: some View {
        switch state {
        case .enabled:  return StatusChip(text: "Enabled", color: Palette.accent)
        case .disabled: return StatusChip(text: "Disabled", color: Palette.danger)
        case .downtime: return StatusChip(text: "Downtime", color: Palette.warn)
        case .override(let until):
            let m = max(0, Int(until.timeIntervalSinceNow / 60))
            return StatusChip(text: "Override · \(m)m left", color: Palette.purple)
        }
    }
    private var meta: String {
        let dns = user.dns_server.isEmpty ? "Default" : "\(user.dns_protocol.rawValue)://\(user.dns_server)"
        return "Port \(user.port) · DNS \(dns)"
    }
}
