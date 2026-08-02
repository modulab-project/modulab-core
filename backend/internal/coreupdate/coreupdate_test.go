package coreupdate

import (
	"testing"
	"time"
)

func TestParseWeekdays(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    map[time.Weekday]bool
		wantErr bool
	}{
		{"single day", "0", map[time.Weekday]bool{time.Sunday: true}, false},
		{"multiple days", "1,3,5", map[time.Weekday]bool{time.Monday: true, time.Wednesday: true, time.Friday: true}, false},
		{"all days", "0,1,2,3,4,5,6", map[time.Weekday]bool{
			time.Sunday: true, time.Monday: true, time.Tuesday: true, time.Wednesday: true,
			time.Thursday: true, time.Friday: true, time.Saturday: true,
		}, false},
		{"whitespace around entries tolerated", " 1 , 2 ", map[time.Weekday]bool{time.Monday: true, time.Tuesday: true}, false},
		{"duplicate entries collapse", "1,1,1", map[time.Weekday]bool{time.Monday: true}, false},
		{"empty string", "", nil, true},
		{"empty entry between commas", "1,,3", nil, true},
		{"trailing comma", "1,2,", nil, true},
		{"out of range negative", "-1", nil, true},
		{"out of range too high", "7", nil, true},
		{"non-numeric token", "monday", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseWeekdays(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseWeekdays(%q): expected error, got %v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseWeekdays(%q): unexpected error: %v", tc.raw, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseWeekdays(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for day := range tc.want {
				if !got[day] {
					t.Fatalf("ParseWeekdays(%q) = %v, missing day %v", tc.raw, got, day)
				}
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantHour   int
		wantMinute int
		wantErr    bool
	}{
		{"midnight", "00:00", 0, 0, false},
		{"end of day", "23:59", 23, 59, false},
		{"single-digit-looking value", "09:05", 9, 5, false},
		{"missing colon", "0900", 0, 0, true},
		{"hour out of range", "24:00", 0, 0, true},
		{"minute out of range", "12:60", 0, 0, true},
		{"negative hour", "-1:00", 0, 0, true},
		{"non-numeric hour", "ab:00", 0, 0, true},
		{"non-numeric minute", "12:cd", 0, 0, true},
		{"empty string", "", 0, 0, true},
		{"extra colon segments", "12:00:00", 0, 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, m, err := ParseTime(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTime(%q): expected error, got (%d, %d)", tc.raw, h, m)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTime(%q): unexpected error: %v", tc.raw, err)
			}
			if h != tc.wantHour || m != tc.wantMinute {
				t.Fatalf("ParseTime(%q) = (%d, %d), want (%d, %d)", tc.raw, h, m, tc.wantHour, tc.wantMinute)
			}
		})
	}
}
