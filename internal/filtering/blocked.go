package filtering

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"golang.org/x/exp/slices"
)

// serviceRules maps a service ID to its filtering rules.
var serviceRules map[string][]*rules.NetworkRule

// serviceIDs contains service IDs sorted alphabetically.
var serviceIDs []string

// initBlockedServices initializes package-level blocked service data.
func initBlockedServices() {
	l := len(blockedServices)
	serviceIDs = make([]string, l)
	serviceRules = make(map[string][]*rules.NetworkRule, l)

	for i, s := range blockedServices {
		netRules := make([]*rules.NetworkRule, 0, len(s.Rules))
		for _, text := range s.Rules {
			rule, err := rules.NewNetworkRule(text, BlockedSvcsListID)
			if err != nil {
				log.Error("parsing blocked service %q rule %q: %s", s.ID, text, err)

				continue
			}

			netRules = append(netRules, rule)
		}

		serviceIDs[i] = s.ID
		serviceRules[s.ID] = netRules
	}

	slices.Sort(serviceIDs)

	log.Debug("filtering: initialized %d services", l)
}

// dayRange is a range within a single day.  Start and End are minutes from the
// start of day, with 0 being 00:00:00.(0) and 1439, 23:59:59.(9).
type dayRange struct {
	start uint16
	end   uint16
}

// maxDayRangeMinutes is the maximum value for DayRange.Start and DayRange.End
// fields, excluding the zero-length range ones.
const maxDayRangeMinutes = 24*60 - 1

// zeroLengthRange returns a new zero-length day range.
func zeroLengthRange() (r dayRange) {
	return dayRange{
		start: 0,
		end:   0,
	}
}

// isZeroLength returns true if r is a zero-length range.
func (r dayRange) isZeroLength() (ok bool) {
	return r.start == 0 && r.end == 0
}

// validate returns the day range validation errors, if any.
func (r dayRange) validate() (err error) {
	defer func() { err = errors.Annotate(err, "bad day range: %w") }()

	switch {
	case r.isZeroLength():
		return nil
	case r.end < r.start:
		return fmt.Errorf("end %d less than start %d", r.end, r.start)
	case r.start > maxDayRangeMinutes:
		return fmt.Errorf("start %d greater than %d", r.start, maxDayRangeMinutes)
	case r.end > maxDayRangeMinutes:
		return fmt.Errorf("end %d greater than %d", r.end, maxDayRangeMinutes)
	default:
		return nil
	}
}

// blockedServicesConfig is the configuration for blocked services.
type blockedServicesConfig struct {
	// IDs is the names of blocked services.
	IDs []string `yaml:"ids"`

	// Schedule is blocked services schedule for every day of the week.
	Schedule blockedSchedule `yaml:"schedule"`
}

// blockedSchedule is the schedule for blocked services.
type blockedSchedule struct {
	// TimeZone is the local time zone.
	TimeZone string `yaml:"time_zone"`

	// Days of the week.

	Sunday    *day `yaml:"sunday"`
	Monday    *day `yaml:"monday"`
	Tuesday   *day `yaml:"tuesday"`
	Wednesday *day `yaml:"wednesday"`
	Thursday  *day `yaml:"thursday"`
	Friday    *day `yaml:"friday"`
	Saturday  *day `yaml:"saturday"`
}

// day is a range within a single day.
type day struct {
	// Start is the duration from the the start of the day.
	Start timeutil.Duration `yaml:"start"`

	// End is the duration from the the start of the day.
	End timeutil.Duration `yaml:"end"`
}

// BlockedServices is the internal structure for blocked services.
type BlockedServices struct {
	// Week is blocked services schedule for every day of the week.
	Week [7]dayRange

	// Location contins local time zone.
	Location *time.Location

	// IDs is the names of blocked services.
	IDs []string
}

func (s *BlockedServices) UnmarshalYAML(unmarshal func(any) error) (err error) {
	conf := &blockedServicesConfig{}

	err = unmarshal(conf)
	if err != nil {
		return err
	}

	bs := BlockedServices{
		IDs: conf.IDs,
	}

	bs.Location, err = time.LoadLocation(conf.Schedule.TimeZone)
	if err != nil {
		return err
	}

	days := []*day{
		conf.Schedule.Sunday,
		conf.Schedule.Monday,
		conf.Schedule.Tuesday,
		conf.Schedule.Wednesday,
		conf.Schedule.Thursday,
		conf.Schedule.Friday,
		conf.Schedule.Saturday,
	}
	for i, d := range days {
		if d == nil {
			bs.Week[i] = zeroLengthRange()

			continue
		}

		bs.Week[i] = dayRange{
			start: uint16(d.Start.Minutes()),
			end:   uint16(d.End.Minutes()),
		}
	}

	for i, r := range bs.Week {
		err = r.validate()
		if err != nil {
			return fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
		}
	}

	*s = bs

	return nil
}

func (s *BlockedServices) MarshalYAML() (v any, err error) {
	schedule := blockedSchedule{
		TimeZone: s.Location.String(),
		Sunday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[0].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[0].end)},
		},
		Monday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[1].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[1].end)},
		},
		Tuesday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[2].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[2].end)},
		},
		Wednesday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[3].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[3].end)},
		},
		Thursday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[4].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[4].end)},
		},
		Friday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[5].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[5].end)},
		},
		Saturday: &day{
			Start: timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[6].start)},
			End:   timeutil.Duration{Duration: time.Minute * time.Duration(s.Week[6].end)},
		},
	}

	conf := blockedServicesConfig{
		IDs:      s.IDs,
		Schedule: schedule,
	}

	return conf, nil
}

// Contains returns true if t is within the allowed schedule.
func (s *BlockedServices) Contains(t time.Time) (ok bool) {
	t = t.In(s.Location)
	r := s.Week[int(t.Weekday())]
	if r.isZeroLength() {
		return false
	}

	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, s.Location)
	start := day.Add(time.Duration(r.start) * time.Minute)
	end := day.Add(time.Duration(r.end+1)*time.Minute - 1*time.Nanosecond)

	return !t.Before(start) && !t.After(end)
}

// BlockedSvcKnown returns true if a blocked service ID is known.
func BlockedSvcKnown(s string) (ok bool) {
	_, ok = serviceRules[s]

	return ok
}

// ApplyBlockedServices - set blocked services settings for this DNS request
func (d *DNSFilter) ApplyBlockedServices(setts *Settings) {
	d.confLock.RLock()
	defer d.confLock.RUnlock()

	setts.ServicesRules = []ServiceEntry{}

	bsvc := d.BlockedServices

	if !bsvc.Contains(time.Now()) {
		return
	}

	d.ApplyBlockedServicesList(setts, bsvc.IDs)
}

func (d *DNSFilter) ApplyBlockedServicesList(setts *Settings, list []string) {
	for _, name := range list {
		rules, ok := serviceRules[name]
		if !ok {
			log.Error("unknown service name: %s", name)

			continue
		}

		setts.ServicesRules = append(setts.ServicesRules, ServiceEntry{
			Name:  name,
			Rules: rules,
		})
	}
}

func (d *DNSFilter) handleBlockedServicesIDs(w http.ResponseWriter, r *http.Request) {
	_ = aghhttp.WriteJSONResponse(w, r, serviceIDs)
}

func (d *DNSFilter) handleBlockedServicesAll(w http.ResponseWriter, r *http.Request) {
	_ = aghhttp.WriteJSONResponse(w, r, struct {
		BlockedServices []blockedService `json:"blocked_services"`
	}{
		BlockedServices: blockedServices,
	})
}

func (d *DNSFilter) handleBlockedServicesList(w http.ResponseWriter, r *http.Request) {
	d.confLock.RLock()
	list := d.Config.BlockedServices
	d.confLock.RUnlock()

	_ = aghhttp.WriteJSONResponse(w, r, list)
}

func (d *DNSFilter) handleBlockedServicesSet(w http.ResponseWriter, r *http.Request) {
	list := []string{}
	err := json.NewDecoder(r.Body).Decode(&list)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json.Decode: %s", err)

		return
	}

	d.confLock.Lock()
	d.Config.BlockedServices.IDs = list
	d.confLock.Unlock()

	log.Debug("Updated blocked services list: %d", len(list))

	d.Config.ConfigModified()
}
