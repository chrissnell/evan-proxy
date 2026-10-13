import XCTest
import SwiftUI
@testable import EvanProxy

final class DowntimeStatusTests: XCTestCase {
    /// Whole-second reference date (2027-01-15 08:00 UTC) so the ceil-to-minute
    /// arithmetic and the RFC3339 round-trip in `user(...)` stay exact.
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

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
        let u = user(downtimeUntil: now.addingTimeInterval(3600),
                     overrideUntil: now.addingTimeInterval(7200))
        guard case .downtimeNow(let until) = UserStatus.state(for: u, now: now) else {
            return XCTFail("expected ad-hoc downtime to win over an active override")
        }
        XCTAssertEqual(until.timeIntervalSince(now), 3600)
    }

    func test_adHocDowntime_outranksSchedule() {
        let u = user(downtimeUntil: now.addingTimeInterval(600),
                     schedule: [String(weekday): [win("07:00", "09:00")]])
        guard case .downtimeNow = UserStatus.state(for: u, now: now, calendar: utc) else {
            return XCTFail("expected ad-hoc downtime")
        }
    }

    func test_expiredAdHocDowntime_isIgnored() {
        let u = user(downtimeUntil: now.addingTimeInterval(-60))
        guard case .enabled = UserStatus.state(for: u, now: now) else {
            return XCTFail("an expired stamp must not read as downtime")
        }
    }

    func test_overrideAlone_isOverride() {
        let u = user(overrideUntil: now.addingTimeInterval(1800))
        guard case .override(let until) = UserStatus.state(for: u, now: now) else {
            return XCTFail("expected override")
        }
        XCTAssertEqual(until.timeIntervalSince(now), 1800)
    }

    func test_expiredOverride_isIgnored() {
        let u = user(overrideUntil: now.addingTimeInterval(-1),
                     schedule: [String(weekday): [win("07:00", "09:00")]])
        guard case .downtime = UserStatus.state(for: u, now: now, calendar: utc) else {
            return XCTFail("an expired override must not keep suppressing the schedule")
        }
    }

    func test_scheduledWindow_isDowntime() {
        let u = user(schedule: [String(weekday): [win("07:00", "09:00")]])
        guard case .downtime = UserStatus.state(for: u, now: now, calendar: utc) else {
            return XCTFail("expected scheduled downtime")
        }
    }

    func test_disabledUser_outranksAdHocDowntime() {
        let u = user(enabled: false, downtimeUntil: now.addingTimeInterval(3600))
        guard case .disabled = UserStatus.state(for: u, now: now) else {
            return XCTFail("expected disabled")
        }
    }

    // --- Flags: what the card's buttons are built from ---

    func test_flags_adHocAndOverrideCoexist() {
        let u = user(downtimeUntil: now.addingTimeInterval(3600),
                     overrideUntil: now.addingTimeInterval(7200))
        let f = UserStatus.flags(for: u, now: now)
        // Both are live, so the card can offer "End Downtime" and still let the
        // pending override be cancelled — as the web UI does.
        XCTAssertNotNil(f.adHocUntil)
        XCTAssertNotNil(f.overrideUntil)
    }

    func test_flags_adHocSuppressesScheduledDowntime() {
        let u = user(downtimeUntil: now.addingTimeInterval(3600),
                     schedule: [String(weekday): [win("07:00", "09:00")]])
        let f = UserStatus.flags(for: u, now: now, calendar: utc)
        // An override cannot lift an ad-hoc block, so no override is offered.
        XCTAssertFalse(f.inScheduledDowntime)
    }

    // --- Pickers and labels ---

    func test_downtimeSheet_offersTheSameDurationsAsTheWeb() {
        XCTAssertEqual(DowntimeSheet.choices.map(\.minutes), [15, 30, 60, 180, 360, 720, 1440, 10080])
        XCTAssertEqual(DowntimeSheet.choices.map(\.label), ["15m", "30m", "1h", "3h", "6h", "12h", "1d", "1w"])
    }

    func test_remainingTime_labels() {
        func label(minutes: Double) -> String {
            RemainingTime.short(until: now.addingTimeInterval(minutes * 60), from: now)
        }
        XCTAssertEqual(label(minutes: 45), "45m")
        XCTAssertEqual(label(minutes: 90), "1h 30m")
        XCTAssertEqual(label(minutes: 120), "2h")
        XCTAssertEqual(label(minutes: 1439), "23h 59m")
        XCTAssertEqual(label(minutes: 1440), "1d")
        XCTAssertEqual(label(minutes: 1500), "1d 1h")
        XCTAssertEqual(label(minutes: 10080), "7d")
        XCTAssertEqual(label(minutes: -5), "0m")
    }

    // --- Fixtures ---

    private var utc: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }
    /// Day-of-week index of `now` in UTC, so schedule fixtures land on it.
    private var weekday: Int { utc.component(.weekday, from: now) - 1 }

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
