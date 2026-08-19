import SwiftUI

/// Bordered container matching the web `.box`.
struct Box<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.bgBox)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(Palette.border, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

/// Large page title matching the dashboard "evan-proxy" heading.
struct PageTitle: View {
    let title: String
    var body: some View {
        Text(title)
            .font(Typography.mono(22, weight: .bold))
            .foregroundStyle(Palette.fg)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Uppercase, letter-spaced section header matching the web `h2`.
struct SectionHeader: View {
    let title: String
    var body: some View {
        Text(title.uppercased())
            .font(Typography.mono(11, weight: .bold))
            .tracking(1.2)
            .foregroundStyle(Palette.fgMuted)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Single status chip: tinted fill + dot + label.
struct StatusChip: View {
    let text: String
    let color: Color
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text).font(Typography.mono(12))
        }
        .padding(.horizontal, 10).padding(.vertical, 4)
        .foregroundStyle(color)
        .background(color.opacity(0.14), in: Capsule())
        .overlay(Capsule().stroke(color, lineWidth: 1))
    }
}

/// Outlined pill button matching the web `.btn-sm`.
struct PillButton: View {
    let title: String
    var color: Color = Palette.fgMuted
    var filled = false
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title).font(Typography.mono(13))
                .padding(.horizontal, 12).padding(.vertical, 6)
                .foregroundStyle(filled ? Palette.bg : color)
                .frame(maxWidth: .infinity)
        }
        .background(filled ? color : .clear, in: RoundedRectangle(cornerRadius: 3))
        .overlay(RoundedRectangle(cornerRadius: 3).stroke(color, lineWidth: 1))
    }
}
