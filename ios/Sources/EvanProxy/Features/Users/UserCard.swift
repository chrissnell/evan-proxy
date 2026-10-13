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
                actions
            }
        }
    }

    private var state: DisplayState { UserStatus.state(for: user) }

    /// Downtime and override buttons, derived the way the web UI derives them:
    /// from independent checks, so a pending override stays reachable while
    /// ad-hoc downtime runs and vice versa. At most two of them exist.
    private var stateActions: [CardAction] {
        let f = UserStatus.flags(for: user)
        guard f.enabled else { return [] }
        var out: [CardAction] = []
        if f.adHocUntil != nil {
            out.append(CardAction(title: "End Downtime", color: Palette.warn, run: onEndDowntime))
        } else if !f.inScheduledDowntime {
            out.append(CardAction(title: "Downtime", color: Palette.warn, run: onDowntime))
        }
        if f.overrideUntil != nil {
            out.append(CardAction(title: "Cancel Override", color: Palette.purple, run: onOverride))
        } else if f.inScheduledDowntime {
            out.append(CardAction(title: "Override", color: Palette.purple, run: onOverride))
        }
        return out
    }

    /// Never more than two buttons on a line: the usual single state action sits
    /// beside Schedule and Edit, and the rarer pair of state actions takes its
    /// own line instead of squeezing five labels into one row.
    @ViewBuilder private var actions: some View {
        let buttons = stateActions
        if buttons.count > 1 {
            VStack(spacing: 6) {
                HStack(spacing: 6) { ForEach(buttons) { pill($0) } }
                HStack(spacing: 6) { editActions }
            }
        } else {
            HStack(spacing: 6) {
                ForEach(buttons) { pill($0) }
                editActions
            }
        }
    }

    @ViewBuilder private var editActions: some View {
        PillButton(title: "Schedule", action: onSchedule)
        PillButton(title: "Edit", action: onEdit)
    }

    private func pill(_ action: CardAction) -> some View {
        PillButton(title: action.title, color: action.color, action: action.run)
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

/// One state-dependent button on a user card.
struct CardAction: Identifiable {
    let title: String
    let color: Color
    let run: () -> Void
    var id: String { title }
}
