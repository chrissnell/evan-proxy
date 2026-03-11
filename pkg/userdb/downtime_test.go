package userdb

import (
	"testing"
	"time"
)

// t constructs a time.Time for a given weekday, hour, minute in a fixed location.
func mkTime(weekday time.Weekday, hour, min int) time.Time {
	// 2024-01-07 is a Sunday (weekday 0)
	day := 7 + int(weekday)
	return time.Date(2024, 1, day, hour, min, 0, 0, time.Local)
}

func TestIsInDowntime_Empty(t *testing.T) {
	if isInDowntime(nil, mkTime(time.Monday, 12, 0)) {
		t.Error("nil schedule should never block")
	}
	if isInDowntime(DowntimeSchedule{}, mkTime(time.Monday, 12, 0)) {
		t.Error("empty schedule should never block")
	}
}

func TestIsInDowntime_SameDay(t *testing.T) {
	sched := DowntimeSchedule{
		"1": {{Start: "08:00", End: "15:00"}}, // Monday
	}

	tests := []struct {
		name    string
		day     time.Weekday
		hour    int
		min     int
		blocked bool
	}{
		{"before window", time.Monday, 7, 59, false},
		{"at start", time.Monday, 8, 0, true},
		{"mid window", time.Monday, 12, 0, true},
		{"at end (exclusive)", time.Monday, 15, 0, false},
		{"after window", time.Monday, 16, 0, false},
		{"different day", time.Tuesday, 12, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInDowntime(sched, mkTime(tt.day, tt.hour, tt.min))
			if got != tt.blocked {
				t.Errorf("got %v, want %v", got, tt.blocked)
			}
		})
	}
}

func TestIsInDowntime_Overnight(t *testing.T) {
	sched := DowntimeSchedule{
		"1": {{Start: "22:00", End: "06:00"}}, // Monday evening -> Tuesday morning
	}

	tests := []struct {
		name    string
		day     time.Weekday
		hour    int
		min     int
		blocked bool
	}{
		{"Monday before window", time.Monday, 21, 59, false},
		{"Monday at start", time.Monday, 22, 0, true},
		{"Monday 23:30", time.Monday, 23, 30, true},
		{"Tuesday 03:00 (spillover)", time.Tuesday, 3, 0, true},
		{"Tuesday 05:59 (spillover)", time.Tuesday, 5, 59, true},
		{"Tuesday 06:00 (end, exclusive)", time.Tuesday, 6, 0, false},
		{"Tuesday 12:00", time.Tuesday, 12, 0, false},
		{"Sunday 03:00 (no Monday schedule yesterday)", time.Sunday, 3, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInDowntime(sched, mkTime(tt.day, tt.hour, tt.min))
			if got != tt.blocked {
				t.Errorf("got %v, want %v", got, tt.blocked)
			}
		})
	}
}

func TestIsInDowntime_OvernightEndMidnight(t *testing.T) {
	// "22:00-00:00" means blocked 22:00-23:59 only (until midnight).
	// start=1320, end=0 -> start >= end -> overnight.
	// Evening portion: now >= 1320 -> blocked.
	// Yesterday spillover: now < 0 -> never true -> correct.
	sched := DowntimeSchedule{
		"1": {{Start: "22:00", End: "00:00"}}, // Monday
	}

	tests := []struct {
		name    string
		day     time.Weekday
		hour    int
		min     int
		blocked bool
	}{
		{"Monday 21:59", time.Monday, 21, 59, false},
		{"Monday 22:00", time.Monday, 22, 0, true},
		{"Monday 23:59", time.Monday, 23, 59, true},
		{"Tuesday 00:00 (end=0, now<0 never true)", time.Tuesday, 0, 0, false},
		{"Tuesday 03:00", time.Tuesday, 3, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInDowntime(sched, mkTime(tt.day, tt.hour, tt.min))
			if got != tt.blocked {
				t.Errorf("got %v, want %v", got, tt.blocked)
			}
		})
	}
}

func TestIsInDowntime_MultiWindow(t *testing.T) {
	sched := DowntimeSchedule{
		"2": { // Tuesday
			{Start: "08:00", End: "15:00"},
			{Start: "22:00", End: "06:00"},
		},
	}

	tests := []struct {
		name    string
		day     time.Weekday
		hour    int
		min     int
		blocked bool
	}{
		{"between windows", time.Tuesday, 16, 0, false},
		{"first window", time.Tuesday, 10, 0, true},
		{"second window evening", time.Tuesday, 23, 0, true},
		{"second window morning (Wed)", time.Wednesday, 4, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInDowntime(sched, mkTime(tt.day, tt.hour, tt.min))
			if got != tt.blocked {
				t.Errorf("got %v, want %v", got, tt.blocked)
			}
		})
	}
}

func TestIsInDowntime_WeekdayWrap(t *testing.T) {
	// Saturday overnight spills into Sunday
	sched := DowntimeSchedule{
		"6": {{Start: "22:00", End: "06:00"}}, // Saturday
	}

	if !isInDowntime(sched, mkTime(time.Saturday, 23, 0)) {
		t.Error("Saturday 23:00 should be blocked")
	}
	if !isInDowntime(sched, mkTime(time.Sunday, 3, 0)) {
		t.Error("Sunday 03:00 should be blocked (Saturday spillover)")
	}
	if isInDowntime(sched, mkTime(time.Sunday, 7, 0)) {
		t.Error("Sunday 07:00 should not be blocked")
	}
}

func TestIsInDowntime_MidnightBoundary(t *testing.T) {
	sched := DowntimeSchedule{
		"1": {{Start: "00:00", End: "06:00"}}, // Monday midnight to 6am
	}

	if !isInDowntime(sched, mkTime(time.Monday, 0, 0)) {
		t.Error("Monday 00:00 should be blocked (same-day, start < end)")
	}
	if !isInDowntime(sched, mkTime(time.Monday, 5, 59)) {
		t.Error("Monday 05:59 should be blocked")
	}
	if isInDowntime(sched, mkTime(time.Monday, 6, 0)) {
		t.Error("Monday 06:00 should not be blocked")
	}
}

func TestValidateSchedule(t *testing.T) {
	tests := []struct {
		name    string
		sched   DowntimeSchedule
		wantErr bool
	}{
		{"empty", DowntimeSchedule{}, false},
		{"valid same-day", DowntimeSchedule{"1": {{Start: "08:00", End: "15:00"}}}, false},
		{"valid overnight", DowntimeSchedule{"1": {{Start: "22:00", End: "06:00"}}}, false},
		{"invalid day key", DowntimeSchedule{"7": {{Start: "08:00", End: "15:00"}}}, true},
		{"invalid day key -1", DowntimeSchedule{"-1": {{Start: "08:00", End: "15:00"}}}, true},
		{"invalid day key abc", DowntimeSchedule{"abc": {{Start: "08:00", End: "15:00"}}}, true},
		{"bad start format", DowntimeSchedule{"1": {{Start: "25:00", End: "15:00"}}}, true},
		{"bad end format", DowntimeSchedule{"1": {{Start: "08:00", End: "60:00"}}}, true},
		{"bad minute", DowntimeSchedule{"1": {{Start: "08:61", End: "15:00"}}}, true},
		{"zero-length window", DowntimeSchedule{"1": {{Start: "08:00", End: "08:00"}}}, true},
		{"non-overlapping", DowntimeSchedule{"1": {
			{Start: "08:00", End: "12:00"},
			{Start: "13:00", End: "17:00"},
		}}, false},
		{"overlapping same-day", DowntimeSchedule{"1": {
			{Start: "08:00", End: "15:00"},
			{Start: "10:00", End: "12:00"},
		}}, true},
		{"overlapping overnight", DowntimeSchedule{"1": {
			{Start: "22:00", End: "06:00"},
			{Start: "23:00", End: "07:00"},
		}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchedule(tt.sched)
			if (err != nil) != tt.wantErr {
				t.Errorf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
