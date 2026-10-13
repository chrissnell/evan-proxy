import XCTest
@testable import EvanProxy

final class DowntimeStatusTests: XCTestCase {
    // Mon 23:00 → inside a 22:00–06:00 Monday window.
    func test_insideWindow_isDowntime() {
        let sched = ["1": [win("22:00", "06:00")]]
        XCTAssertTrue(UserStatus.inDowntime(schedule: sched, weekday: 1, minutesOfDay: 23*60))
    }
    // Tue 03:00 → covered by Monday's overnight spillover.
    func test_overnightSpillover_isDowntime() {
        let sched = ["1": [win("22:00", "06:00")]]
        XCTAssertTrue(UserStatus.inDowntime(schedule: sched, weekday: 2, minutesOfDay: 3*60))
    }
    func test_outsideWindow_isNotDowntime() {
        let sched = ["1": [win("22:00", "06:00")]]
        XCTAssertFalse(UserStatus.inDowntime(schedule: sched, weekday: 1, minutesOfDay: 12*60))
    }

    // --- Display state precedence (mirrors the server's IsInDowntime) ---

    func test_adHocDowntime_outranksOverride() {
        let now = Date()
        let u = user(downtimeUntil: now.addingTimeInterval(3600),
                     overrideUntil: now.addingTimeInterval(7200))
        guard case .downtimeNow(let until) = UserStatus.state(for: u, now: now) else {
            return XCTFail("expected ad-hoc downtime to win over an active override")
        }
        XCTAssertEqual(until.timeIntervalSince(now), 3600, accuracy: 1)
    }

    func test_adHocDowntime_outranksSchedule() {
        let now = Date()
        let u = user(downtimeUntil: now.addingTimeInterval(600),
                     schedule: ["1": [win("22:00", "06:00")]])
        guard case .downtimeNow = UserStatus.state(for: u, now: now) else {
            return XCTFail("expected ad-hoc downtime")
        }
    }

    func test_expiredAdHocDowntime_isIgnored() {
        let now = Date()
        let u = user(downtimeUntil: now.addingTimeInterval(-60))
        guard case .enabled = UserStatus.state(for: u, now: now) else {
            return XCTFail("an expired stamp must not read as downtime")
        }
    }

    func test_disabledUser_outranksAdHocDowntime() {
        let now = Date()
        let u = user(enabled: false, downtimeUntil: now.addingTimeInterval(3600))
        guard case .disabled = UserStatus.state(for: u, now: now) else {
            return XCTFail("expected disabled")
        }
    }

    // --- Remaining-time labels ---

    func test_remainingTime_labels() {
        // Whole-second reference date so the ceil-to-minute arithmetic is exact.
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        func label(minutes: Double) -> String {
            RemainingTime.short(until: now.addingTimeInterval(minutes * 60), from: now)
        }
        XCTAssertEqual(label(minutes: 45), "45m")
        XCTAssertEqual(label(minutes: 90), "1h 30m")
        XCTAssertEqual(label(minutes: 120), "2h")
        XCTAssertEqual(label(minutes: 1500), "1d 1h")
        XCTAssertEqual(label(minutes: 10080), "7d")
        XCTAssertEqual(label(minutes: -5), "0m")
    }

    private func win(_ s: String, _ e: String) -> Components.Schemas.DowntimeWindow {
        .init(start: s, end: e)
    }

    private func user(enabled: Bool = true, downtimeUntil: Date? = nil, overrideUntil: Date? = nil,
                      schedule: [String: [Components.Schemas.DowntimeWindow]]? = nil)
                      -> Components.Schemas.UserInfo {
        let sched: Components.Schemas.DowntimeSchedule? = schedule.map {
            Components.Schemas.DowntimeSchedule(additionalProperties: $0)
        }
        let fmt = ISO8601DateFormatter()
        return .init(username: "evan", created_at: "2026-01-01T00:00:00Z", dns_server: "",
                     dns_protocol: ._empty, port: 4100, enabled: enabled,
                     downtime_schedule: sched,
                     downtime_override_until: overrideUntil.map { fmt.string(from: $0) },
                     downtime_until: downtimeUntil.map { fmt.string(from: $0) })
    }
}
