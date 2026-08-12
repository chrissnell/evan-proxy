import SwiftUI
import Charts

/// Human-readable byte size, matching the web UI's `fmtBytes` (1024-based).
enum ByteFormat {
    static func string(_ b: Int) -> String {
        let x = Double(b)
        if b < 1024 { return "\(b) B" }
        if b < 1_048_576 { return String(format: "%.1f KB", x / 1024) }
        if b < 1_073_741_824 { return String(format: "%.1f MB", x / 1_048_576) }
        return String(format: "%.1f GB", x / 1_073_741_824)
    }
}

struct TrafficChart: View {
    let buckets: [Components.Schemas.TrafficBucket]
    let value: (Components.Schemas.TrafficBucket) -> Int
    /// Formats a raw value for axis ticks and the hover popup (bytes vs. plain count).
    var format: (Int) -> String = { "\($0)" }

    @State private var selectedTime: Date?

    private struct Point: Identifiable {
        let id: Int
        let time: Date
        let value: Int
    }

    private var points: [Point] {
        buckets.enumerated().map { i, b in
            Point(id: i, time: Date(timeIntervalSince1970: Double(b.t)), value: value(b))
        }
    }

    private var selected: Point? {
        guard let selectedTime, !points.isEmpty else { return nil }
        return points.min {
            abs($0.time.timeIntervalSince(selectedTime)) < abs($1.time.timeIntervalSince(selectedTime))
        }
    }

    var body: some View {
        if points.isEmpty {
            Text("no data")
                .font(Typography.mono(12)).foregroundStyle(Palette.fgDim)
                .frame(maxWidth: .infinity, minHeight: 140)
        } else {
            Chart {
                ForEach(points) { p in
                    AreaMark(x: .value("time", p.time), y: .value("value", p.value))
                        .foregroundStyle(Palette.accent.opacity(0.15))
                    LineMark(x: .value("time", p.time), y: .value("value", p.value))
                        .foregroundStyle(Palette.accent.opacity(0.7))
                }
                if let s = selected {
                    RuleMark(x: .value("time", s.time))
                        .foregroundStyle(Palette.fgMuted.opacity(0.5))
                        .annotation(position: .top,
                                    overflowResolution: .init(x: .fit(to: .chart), y: .disabled)) {
                            popup(s)
                        }
                    PointMark(x: .value("time", s.time), y: .value("value", s.value))
                        .foregroundStyle(Palette.accent)
                }
            }
            .chartXSelection(value: $selectedTime)
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 4)) {
                    AxisGridLine().foregroundStyle(Palette.border.opacity(0.4))
                    AxisValueLabel(format: .dateTime.hour().minute())
                        .font(Typography.mono(9)).foregroundStyle(Palette.fgMuted)
                }
            }
            .chartYAxis {
                AxisMarks(values: .automatic(desiredCount: 3)) { v in
                    AxisGridLine().foregroundStyle(Palette.border.opacity(0.4))
                    AxisValueLabel {
                        if let d = v.as(Double.self) {
                            Text(format(Int(d)))
                                .font(Typography.mono(9)).foregroundStyle(Palette.fgMuted)
                        }
                    }
                }
            }
            .frame(height: 140)
        }
    }

    private func popup(_ p: Point) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(p.time, format: .dateTime.hour().minute())
                .font(Typography.mono(10)).foregroundStyle(Palette.fgMuted)
            Text(format(p.value))
                .font(Typography.mono(12, weight: .bold)).foregroundStyle(Palette.fg)
        }
        .padding(6)
        .background(Palette.bgBox, in: RoundedRectangle(cornerRadius: 3))
        .overlay(RoundedRectangle(cornerRadius: 3).stroke(Palette.border, lineWidth: 1))
    }
}
