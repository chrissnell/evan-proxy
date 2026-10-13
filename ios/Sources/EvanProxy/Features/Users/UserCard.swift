import SwiftUI

struct UserCard: View {
    let user: Components.Schemas.UserInfo
    let onToggle: (Bool) -> Void
    let onSchedule: () -> Void
    let onEdit: () -> Void
    let onOverride: () -> Void
    let onDowntime: () -> Void
    let onEndDowntime: () -> Void

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
                // One state-dependent action at most, so the row never crowds
                // past three buttons at any width.
                HStack(spacing: 6) {
                    stateAction
                    PillButton(title: "Schedule", action: onSchedule)
                    PillButton(title: "Edit", action: onEdit)
                }
            }
        }
    }

    private var state: DisplayState { UserStatus.state(for: user) }

    @ViewBuilder private var stateAction: some View {
        switch state {
        case .downtimeNow:
            PillButton(title: "End Downtime", color: Palette.warn, action: onEndDowntime)
        case .override:
            PillButton(title: "Cancel Override", color: Palette.purple, action: onOverride)
        case .downtime:
            PillButton(title: "Override", color: Palette.purple, action: onOverride)
        case .enabled:
            PillButton(title: "Downtime", color: Palette.warn, action: onDowntime)
        case .disabled:
            EmptyView()
        }
    }

    private var chip: some View {
        switch state {
        case .enabled:  return StatusChip(text: "Enabled", color: Palette.accent)
        case .disabled: return StatusChip(text: "Disabled", color: Palette.danger)
        case .downtime: return StatusChip(text: "Downtime", color: Palette.warn)
        case .downtimeNow(let until):
            return StatusChip(text: "Downtime · \(RemainingTime.short(until: until)) left", color: Palette.warn)
        case .override(let until):
            return StatusChip(text: "Override · \(RemainingTime.short(until: until)) left", color: Palette.purple)
        }
    }
    private var meta: String {
        let dns = user.dns_server.isEmpty ? "Default" : "\(user.dns_protocol.rawValue)://\(user.dns_server)"
        return "Port \(user.port) · DNS \(dns)"
    }
}
