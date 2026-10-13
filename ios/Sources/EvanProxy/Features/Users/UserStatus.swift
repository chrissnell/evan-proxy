import Foundation

enum DisplayState {
    case enabled, disabled, downtime
    case override(until: Date)
    /// Admin-started ad-hoc downtime. Outranks both the schedule and an override,
    /// matching the server's IsInDowntime precedence.
    case downtimeNow(until: Date)
}

enum UserStatus {
    /// The independent facts behind a user's status. The chip collapses these
    /// into one DisplayState; the action buttons need them separately, because
    /// ad-hoc downtime and an override can be pending at the same time.
    struct Flags {
        let enabled: Bool
        let adHocUntil: Date?
        let overrideUntil: Date?
        /// Scheduled downtime, already suppressed while ad-hoc downtime runs —
        /// an override cannot lift an ad-hoc block, so the app must not offer one.
        let inScheduledDowntime: Bool
    }

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

    static func flags(for u: Components.Schemas.UserInfo, now: Date = Date(),
                      calendar: Calendar = .current) -> Flags {
        let adHoc = expiry(u.downtime_until, after: now)
        let comps = calendar.dateComponents([.weekday, .hour, .minute], from: now)
        let weekday = (comps.weekday ?? 1) - 1            // Calendar: 1=Sun → 0=Sun
        let minutes = (comps.hour ?? 0) * 60 + (comps.minute ?? 0)
        let scheduled = adHoc == nil && inDowntime(
            schedule: u.downtime_schedule?.additionalProperties ?? [:],
            weekday: weekday, minutesOfDay: minutes)
        return Flags(enabled: u.enabled, adHocUntil: adHoc,
                     overrideUntil: expiry(u.downtime_override_until, after: now),
                     inScheduledDowntime: scheduled)
    }

    static func state(for u: Components.Schemas.UserInfo, now: Date = Date(),
                      calendar: Calendar = .current) -> DisplayState {
        let f = flags(for: u, now: now, calendar: calendar)
        if !f.enabled { return .disabled }
        if let until = f.adHocUntil { return .downtimeNow(until: until) }
        if let until = f.overrideUntil { return .override(until: until) }
        return f.inScheduledDowntime ? .downtime : .enabled
    }

    /// Parses an RFC3339 deadline, treating a missing or already-passed one as nil
    /// — the server clears expired stamps lazily, so the app must ignore them.
    /// The formatter is built per call: ISO8601DateFormatter is a non-Sendable
    /// class, so a shared static would need a concurrency opt-out to compile
    /// under the package's Swift 6 language mode.
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
