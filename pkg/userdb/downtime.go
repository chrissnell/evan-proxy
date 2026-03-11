package userdb

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DowntimeWindow represents a blocked time period within a day.
type DowntimeWindow struct {
	Start string `json:"start"` // "HH:MM"
	End   string `json:"end"`   // "HH:MM"
}

// DowntimeSchedule maps day-of-week ("0"=Sunday .. "6"=Saturday) to blocked windows.
type DowntimeSchedule map[string][]DowntimeWindow

// parseHHMM converts "HH:MM" to minutes since midnight.
func parseHHMM(s string) (int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time format: %q", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour in %q", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute in %q", s)
	}
	return h*60 + m, nil
}

// ValidateSchedule checks that a schedule has valid day keys, time formats,
// non-zero-length windows, and no overlapping windows on the same day.
func ValidateSchedule(s DowntimeSchedule) error {
	for dayKey, windows := range s {
		day, err := strconv.Atoi(dayKey)
		if err != nil || day < 0 || day > 6 {
			return fmt.Errorf("invalid day key %q: must be 0-6", dayKey)
		}
		for _, w := range windows {
			startMin, err := parseHHMM(w.Start)
			if err != nil {
				return fmt.Errorf("day %s: %w", dayKey, err)
			}
			endMin, err := parseHHMM(w.End)
			if err != nil {
				return fmt.Errorf("day %s: %w", dayKey, err)
			}
			if startMin == endMin {
				return fmt.Errorf("day %s: zero-length window %s-%s", dayKey, w.Start, w.End)
			}
		}
		if err := checkOverlaps(dayKey, windows); err != nil {
			return err
		}
	}
	return nil
}

// checkOverlaps detects overlapping windows on the same day.
// Overnight windows (start >= end) are treated as [start, 1440) + [0, end).
func checkOverlaps(dayKey string, windows []DowntimeWindow) error {
	if len(windows) < 2 {
		return nil
	}

	// Convert to intervals in minutes, expanding overnight windows
	type interval struct {
		start, end int
		idx        int
	}
	var intervals []interval
	for i, w := range windows {
		s, _ := parseHHMM(w.Start)
		e, _ := parseHHMM(w.End)
		if s < e {
			intervals = append(intervals, interval{s, e, i})
		} else {
			// Overnight: split into [start,1440) and [0,end)
			intervals = append(intervals, interval{s, 1440, i})
			if e > 0 {
				intervals = append(intervals, interval{0, e, i})
			}
		}
	}

	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].start < intervals[j].start
	})

	for i := 1; i < len(intervals); i++ {
		if intervals[i].start < intervals[i-1].end {
			return fmt.Errorf("day %s: overlapping windows", dayKey)
		}
	}
	return nil
}

// isInDowntime returns whether the given time falls within any blocked window.
// Uses server local time — this is deliberate for simplicity with household schedules.
func isInDowntime(schedule DowntimeSchedule, now time.Time) bool {
	if len(schedule) == 0 {
		return false
	}

	nowMin := now.Hour()*60 + now.Minute()
	today := strconv.Itoa(int(now.Weekday()))
	yesterday := strconv.Itoa(int((now.Weekday() + 6) % 7))

	// Check today's windows
	for _, w := range schedule[today] {
		s, _ := parseHHMM(w.Start)
		e, _ := parseHHMM(w.End)
		if s < e {
			// Same-day window (e.g. 08:00-15:00)
			if nowMin >= s && nowMin < e {
				return true
			}
		} else {
			// Overnight window (e.g. 22:00-06:00): evening portion
			if nowMin >= s {
				return true
			}
		}
	}

	// Check yesterday's windows for overnight spillover into today
	for _, w := range schedule[yesterday] {
		s, _ := parseHHMM(w.Start)
		e, _ := parseHHMM(w.End)
		if s >= e {
			// Overnight window: morning portion from yesterday's schedule
			if nowMin < e {
				return true
			}
		}
	}

	return false
}
