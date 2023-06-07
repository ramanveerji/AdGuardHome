package schedule

import (
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestWeekly_Contains(t *testing.T) {
	baseTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	otherTime := baseTime.Add(1 * timeutil.Day)

	// NOTE: In the Etc area the sign of the offsets is flipped.  So, Etc/GMT-3
	// is actually UTC+03:00.
	otherTZ := time.FixedZone("Etc/GMT-3", 3*60*60)

	// baseSchedule, 12:00 to 14:00.
	baseSchedule := &Weekly{
		days: [7]DayRange{
			{},
			{},
			{},
			{},
			{},
			// baseTime is on Friday.
			{Start: 12 * time.Hour, End: 14 * time.Hour},
			{},
		},
		location: time.UTC,
	}

	// allDaySchedule, 00:00 to 24:00.
	allDaySchedule := &Weekly{
		days: [7]DayRange{
			{},
			{},
			{},
			{},
			{},
			// baseTime is on Friday.
			{Start: 0, End: 24 * time.Hour},
			{},
		},
		location: time.UTC,
	}

	// oneMinSchedule, 00:00 to 00:01.
	oneMinSchedule := &Weekly{
		days: [7]DayRange{
			{},
			{},
			{},
			{},
			{},
			// baseTime is on Friday.
			{Start: 0, End: 1 * time.Minute},
			{},
		},
		location: time.UTC,
	}

	testCases := []struct {
		schedule *Weekly
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

func TestWeekly_UnmarshalYAML(t *testing.T) {
	const brusselsSunday = `
sun:
    start: 12h
    end: 14h
time_zone: Europe/Brussels
`
	const sameTime = `
sun:
    start: 9h
    end: 9h
`
	brussels, err := time.LoadLocation("Europe/Brussels")
	require.NoError(t, err)

	brusselsWeekly := &Weekly{
		days: [7]DayRange{{
			Start: time.Hour * 12,
			End:   time.Hour * 14,
		}},
		location: brussels,
	}

	testCases := []struct {
		name       string
		wantErrMsg string
		data       []byte
		want       *Weekly
	}{{
		name:       "empty",
		wantErrMsg: "",
		data:       []byte(""),
		want:       &Weekly{},
	}, {
		name:       "null",
		wantErrMsg: "",
		data:       []byte("null"),
		want:       &Weekly{},
	}, {
		name:       "brussels_sunday",
		wantErrMsg: "",
		data:       []byte(brusselsSunday),
		want:       brusselsWeekly,
	}, {
		name:       "start_equal_end",
		wantErrMsg: "weekday Sunday: bad day range: start 9h0m0s is greater or equal to end 9h0m0s",
		data:       []byte(sameTime),
		want:       &Weekly{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &Weekly{}
			err = yaml.Unmarshal(tc.data, w)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			assert.Equal(t, tc.want, w)
		})
	}

	t.Run("marshal", func(t *testing.T) {
		var data []byte
		data, err = yaml.Marshal(brusselsWeekly)
		require.NoError(t, err)

		w := &Weekly{}
		err = yaml.Unmarshal(data, w)
		require.NoError(t, err)

		assert.Equal(t, brusselsWeekly, w)
	})
}
