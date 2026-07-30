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
    private func win(_ s: String, _ e: String) -> Components.Schemas.DowntimeWindow {
        .init(start: s, end: e)
    }
}
