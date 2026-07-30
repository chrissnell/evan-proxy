import Foundation

enum DisplayState { case enabled, disabled, downtime, override(until: Date) }

enum UserStatus {
    /// Mirrors the web UI's checkDowntimeClient: keys are "0"(Sun)…"6"(Sat).
    static func inDowntime(schedule: [String: [Components.Schemas.DowntimeWindow]],
                           weekday: Int, minutesOfDay now: Int) -> Bool {
        func mins(_ hhmm: String) -> Int {
            let p = hhmm.split(separator: ":"); return (Int(p[0]) ?? 0) * 60 + (Int(p[1]) ?? 0)
        }
        for w in schedule[String(weekday)] ?? [] {
            let s = mins(w.start), e = mins(w.end)
            if s < e { if now >= s && now < e { return true } }
            else { if now >= s { return true } }         // overnight, evening side
        }
        let yesterday = (weekday + 6) % 7
        for w in schedule[String(yesterday)] ?? [] {
            let s = mins(w.start), e = mins(w.end)
            if s >= e && now < e { return true }          // overnight spillover into today
        }
        return false
    }

    static func state(for u: Components.Schemas.UserInfo, now: Date = Date(),
                      calendar: Calendar = .current) -> DisplayState {
        if !u.enabled { return .disabled }
        if let untilStr = u.downtime_override_until,
           let until = ISO8601DateFormatter().date(from: untilStr), until > now {
            return .override(until: until)
        }
        let comps = calendar.dateComponents([.weekday, .hour, .minute], from: now)
        let weekday = (comps.weekday ?? 1) - 1            // Calendar: 1=Sun → 0=Sun
        let minutes = (comps.hour ?? 0) * 60 + (comps.minute ?? 0)
        if inDowntime(schedule: u.downtime_schedule?.additionalProperties ?? [:],
                      weekday: weekday, minutesOfDay: minutes) { return .downtime }
        return .enabled
    }
}
