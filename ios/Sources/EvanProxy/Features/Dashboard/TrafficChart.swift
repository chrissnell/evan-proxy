import SwiftUI
import Charts

struct TrafficChart: View {
    let buckets: [Components.Schemas.TrafficBucket]
    let value: (Components.Schemas.TrafficBucket) -> Int
    var body: some View {
        Chart(Array(buckets.enumerated()), id: \.offset) { i, b in
            AreaMark(x: .value("t", i), y: .value("v", value(b)))
                .foregroundStyle(Palette.accent.opacity(0.15))
            LineMark(x: .value("t", i), y: .value("v", value(b)))
                .foregroundStyle(Palette.accent.opacity(0.7))
        }
        .chartXAxis(.hidden).chartYAxis(.hidden).frame(height: 120)
    }
}
