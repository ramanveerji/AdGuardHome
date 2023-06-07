// Package schedule provides types for scheduling.
package schedule

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"gopkg.in/yaml.v3"
)

// Weekly is a schedule for one week.  Each day of the week has one range with
// a beginning and an end.
type Weekly struct {
	// timeZone defines the location to be used to calculate the offsets of the
	// day ranges.
	Location *time.Location

	// days are the day ranges of this schedule.  The indexes of this array are
	// the [time.Weekday] values.
	Days [7]DayRange
}

// Contains returns true if t is within the corresponding day range of the
// schedule in the schedule's time zone.
func (w *Weekly) Contains(t time.Time) (ok bool) {
	t = t.In(w.Location)
	wd := t.Weekday()
	dr := w.Days[wd]

	// Calculate the offset of the day range.
	y, m, d := t.Date()
	day := time.Date(y, m, d, 0, 0, 0, 0, w.Location)
	offset := t.Sub(day)

	return dr.contains(offset)
}

// type check
var _ yaml.Unmarshaler = (*Weekly)(nil)

// UnmarshalYAML implements the [yaml.Unmarshaler] interface for *Weekly.
func (w *Weekly) UnmarshalYAML(value *yaml.Node) (err error) {
	conf := &weeklyConfig{}

	err = value.Decode(conf)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	weekly := Weekly{}

	weekly.Location, err = time.LoadLocation(conf.TimeZone)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	days := []dayConfig{
		conf.Sunday,
		conf.Monday,
		conf.Tuesday,
		conf.Wednesday,
		conf.Thursday,
		conf.Friday,
		conf.Saturday,
	}
	for i, d := range days {
		r := DayRange{
			Start: d.Start.Duration,
			End:   d.End.Duration,
		}

		err = validate(r)
		if err != nil {
			return fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
		}

		weekly.Days[i] = r
	}

	*w = weekly

	return nil
}

// maxDayRange is the maximum value for day range end.
const maxDayRange = 24 * time.Hour

// validate returns the day range validation errors, if any.
func validate(r DayRange) (err error) {
	defer func() { err = errors.Annotate(err, "bad day range: %w") }()

	start := r.Start.Truncate(time.Minute)
	end := r.End.Truncate(time.Minute)

	switch {
	case r == DayRange{}:
		return nil
	case start != r.Start:
		return fmt.Errorf("start %s isn't rounded to minutes", r.Start)
	case end != r.End:
		return fmt.Errorf("end %s isn't rounded to minutes", r.End)
	case r.Start < 0:
		return fmt.Errorf("start %s is negative", r.Start)
	case r.End < 0:
		return fmt.Errorf("end %s is negative", r.End)
	case r.Start >= r.End:
		return fmt.Errorf("start %s is greater or equal to end %s", r.Start, r.End)
	case r.Start >= maxDayRange:
		return fmt.Errorf("start %s is greater or equal to %s", r.Start, maxDayRange)
	case r.End > maxDayRange:
		return fmt.Errorf("end %s is greater than %s", r.End, maxDayRange)
	default:
		return nil
	}
}

// type check
var _ yaml.Marshaler = (*Weekly)(nil)

// MarshalYAML implements the [yaml.Marshaler] interface for *Weekly.
func (w *Weekly) MarshalYAML() (v any, err error) {
	return weeklyConfig{
		TimeZone: w.Location.String(),
		Sunday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Sunday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Sunday].End},
		},
		Monday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Monday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Monday].End},
		},
		Tuesday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Tuesday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Tuesday].End},
		},
		Wednesday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Wednesday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Wednesday].End},
		},
		Thursday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Thursday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Thursday].End},
		},
		Friday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Friday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Friday].End},
		},
		Saturday: dayConfig{
			Start: timeutil.Duration{Duration: w.Days[time.Saturday].Start},
			End:   timeutil.Duration{Duration: w.Days[time.Saturday].End},
		},
	}, nil
}

// DayRange represents a single interval within a day.  The interval begins at
// Start and ends before End.  That is, it contains a time point T if Start <=
// T < End.
type DayRange struct {
	// Start is an offset from the beginning of the day.  It must be greater
	// than or equal to zero and less than 24h.
	Start time.Duration

	// End is an offset from the beginning of the day.  It must be greater than
	// or equal to zero and less than or equal to 24h.
	End time.Duration
}

// contains returns true if Start <= offset < End.
func (r *DayRange) contains(offset time.Duration) (ok bool) {
	return r.Start <= offset && offset < r.End
}

// weeklyConfig is the YAML configuration structure of Weekly.
type weeklyConfig struct {
	// Days of the week.

	Sunday    dayConfig `yaml:"sun"`
	Monday    dayConfig `yaml:"mon"`
	Tuesday   dayConfig `yaml:"tue"`
	Wednesday dayConfig `yaml:"wed"`
	Thursday  dayConfig `yaml:"thu"`
	Friday    dayConfig `yaml:"fri"`
	Saturday  dayConfig `yaml:"sat"`

	// TimeZone is the local time zone.
	TimeZone string `yaml:"time_zone"`
}

// dayConfig is the YAML configuration structure of DayRange.
type dayConfig struct {
	Start timeutil.Duration `yaml:"start"`
	End   timeutil.Duration `yaml:"end"`
}
