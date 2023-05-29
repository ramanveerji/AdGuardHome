package filtering

import (
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
)

func TestBlockedServices_Contains(t *testing.T) {
	baseTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	otherTime := baseTime.Add(1 * timeutil.Day)

	// NOTE: In the Etc area the sign of the offsets is flipped.  So, Etc/GMT-3
	// is actually UTC+03:00.
	otherTZ := time.FixedZone("Etc/GMT-3", 3*60*60)

	// baseSchedule, 12:00:00 to 13:59:59.
	baseSchedule := &BlockedServices{
		Week: [7]dayRange{
			zeroLengthRange(),
			zeroLengthRange(),
			zeroLengthRange(),
			zeroLengthRange(),
			zeroLengthRange(),
			// baseTime is on Friday.
			{start: 12 * time.Hour, end: 14*time.Hour - 1*time.Minute},
			zeroLengthRange(),
		},
		Location: time.UTC,
	}

	// allDaySchedule, 00:00:00 to 23:59:59.
	allDaySchedule := &BlockedServices{
		Week: [7]dayRange{
			zeroLengthRange(),
			zeroLengthRange(),
			zeroLengthRange(),
			zeroLengthRange(),
			zeroLengthRange(),
			// baseTime is on Friday.
			{start: 0, end: 24*time.Hour - 1*time.Minute},
			zeroLengthRange(),
		},
		Location: time.UTC,
	}

	testCases := []struct {
		schedule *BlockedServices
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
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, tc.schedule.Contains(tc.t))
		})
	}
}
