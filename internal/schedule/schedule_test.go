package schedule_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
)

func TestWeekly_Contains(t *testing.T) {
	baseTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	otherTime := baseTime.Add(1 * timeutil.Day)

	// NOTE: In the Etc area the sign of the offsets is flipped.  So, Etc/GMT-3
	// is actually UTC+03:00.
	otherTZ := time.FixedZone("Etc/GMT-3", 3*60*60)

	// baseSchedule, 12:00 to 14:00.
	baseSchedule := &schedule.Weekly{
		Days: [7]schedule.DayRange{
			{},
			{},
			{},
			{},
			{},
			// baseTime is on Friday.
			{Start: 12 * time.Hour, End: 14 * time.Hour},
			{},
		},
		Location: time.UTC,
	}

	// allDaySchedule, 00:00 to 24:00.
	allDaySchedule := &schedule.Weekly{
		Days: [7]schedule.DayRange{
			{},
			{},
			{},
			{},
			{},
			// baseTime is on Friday.
			{Start: 0, End: 24 * time.Hour},
			{},
		},
		Location: time.UTC,
	}

	// oneMinSchedule, 00:00 to 00:01.
	oneMinSchedule := &schedule.Weekly{
		Days: [7]schedule.DayRange{
			{},
			{},
			{},
			{},
			{},
			// baseTime is on Friday.
			{Start: 0, End: 1 * time.Minute},
			{},
		},
		Location: time.UTC,
	}

	testCases := []struct {
		schedule *schedule.Weekly
		assert   assert.BoolAssertionFunc
		t        time.Time
		name     string
	}{{
		schedule: allDaySchedule,
		assert:   assert.True,
		t:        baseTime,
		name:     "same_day_all_day",
	}, {
		schedule: baseSchedule,
		assert:   assert.True,
		t:        baseTime.Add(13 * time.Hour),
		name:     "same_day_inside",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        baseTime.Add(11 * time.Hour),
		name:     "same_day_outside",
	}, {
		schedule: allDaySchedule,
		assert:   assert.True,
		t:        baseTime.Add(24*time.Hour - time.Second),
		name:     "same_day_last_second",
	}, {
		schedule: allDaySchedule,
		assert:   assert.False,
		t:        otherTime,
		name:     "other_day_all_day",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        otherTime.Add(13 * time.Hour),
		name:     "other_day_inside",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        otherTime.Add(11 * time.Hour),
		name:     "other_day_outside",
	}, {
		schedule: baseSchedule,
		assert:   assert.True,
		t:        baseTime.Add(13 * time.Hour).In(otherTZ),
		name:     "same_day_inside_other_tz",
	}, {
		schedule: baseSchedule,
		assert:   assert.False,
		t:        baseTime.Add(11 * time.Hour).In(otherTZ),
		name:     "same_day_outside_other_tz",
	}, {
		schedule: oneMinSchedule,
		assert:   assert.True,
		t:        baseTime,
		name:     "one_minute_beginning",
	}, {
		schedule: oneMinSchedule,
		assert:   assert.True,
		t:        baseTime.Add(1*time.Minute - 1),
		name:     "one_minute_end",
	}, {
		schedule: oneMinSchedule,
		assert:   assert.False,
		t:        baseTime.Add(1 * time.Minute),
		name:     "one_minute_past_end",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, tc.schedule.Contains(tc.t))
		})
	}
}
