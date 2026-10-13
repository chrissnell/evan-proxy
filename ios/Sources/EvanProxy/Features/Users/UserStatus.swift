import Foundation

enum DisplayState {
    case enabled, disabled, downtime
    case override(until: Date)
    /// Admin-started ad-hoc downtime. Outranks both the schedule and an override,
    /// matching the server's IsInDowntime precedence.
    case downtimeNow(until: Date)
}

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
        if let until = expiry(u.downtime_until, after: now) { return .downtimeNow(until: until) }
        if let until = expiry(u.downtime_override_until, after: now) { return .override(until: until) }
        let comps = calendar.dateComponents([.weekday, .hour, .minute], from: now)
        let weekday = (comps.weekday ?? 1) - 1            // Calendar: 1=Sun → 0=Sun
        let minutes = (comps.hour ?? 0) * 60 + (comps.minute ?? 0)
        if inDowntime(schedule: u.downtime_schedule?.additionalProperties ?? [:],
                      weekday: weekday, minutesOfDay: minutes) { return .downtime }
        return .enabled
    }

    /// Parses an RFC3339 deadline, treating a missing or already-passed one as nil
    /// — the server clears expired stamps lazily, so the app must ignore them.
    private static func expiry(_ raw: String?, after now: Date) -> Date? {
        guard let raw, let date = ISO8601DateFormatter().date(from: raw), date > now else { return nil }
        return date
    }
}

/// Compact "time left" label for status chips. Mirrors the web fmtRemaining but
/// adds a day unit, so week-long ad-hoc downtime reads "7d" rather than "168h".
enum RemainingTime {
    static func short(until: Date, from now: Date = Date()) -> String {
        let totalMinutes = Int((until.timeIntervalSince(now) / 60).rounded(.up))
        guard totalMinutes > 0 else { return "0m" }
        if totalMinutes < 60 { return "\(totalMinutes)m" }
        let hours = totalMinutes / 60, minutes = totalMinutes % 60
        if hours < 24 { return minutes > 0 ? "\(hours)h \(minutes)m" : "\(hours)h" }
        let days = hours / 24, leftoverHours = hours % 24
        return leftoverHours > 0 ? "\(days)d \(leftoverHours)h" : "\(days)d"
    }
}
