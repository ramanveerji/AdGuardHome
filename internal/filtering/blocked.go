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
	"gopkg.in/yaml.v3"
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
	start time.Duration
	end   time.Duration
}

// maxDayRangeMinutes is the maximum value for dayRange.Start and dayRange.End
// fields, excluding the zero-length range ones.
const maxDayRangeMinutes = 24*time.Hour - 1*time.Minute

// validate returns the day range validation errors, if any.
func (r dayRange) validate() (err error) {
	defer func() { err = errors.Annotate(err, "bad day range: %w") }()

	start := r.start.Truncate(time.Minute)
	end := r.end.Truncate(time.Minute)

	switch {
	case r == dayRange{}:
		return nil
	case start != r.start:
		return fmt.Errorf("start %s isn't rounded to minutes", r.start)
	case end != r.end:
		return fmt.Errorf("end %s isn't rounded to minutes", r.end)
	case r.end < r.start:
		return fmt.Errorf("end %s less than start %s", r.end, r.start)
	case r.start > maxDayRangeMinutes:
		return fmt.Errorf("start %s greater than %s", r.start, maxDayRangeMinutes)
	case r.end > maxDayRangeMinutes:
		return fmt.Errorf("end %s greater than %s", r.end, maxDayRangeMinutes)
	default:
		return nil
	}
}

// blockedScheduleConfig is the configuration of blocked schedule.
type blockedScheduleConfig struct {
	// Days of the week.

	Sunday    *day `yaml:"sun"`
	Monday    *day `yaml:"mon"`
	Tuesday   *day `yaml:"tue"`
	Wednesday *day `yaml:"wed"`
	Thursday  *day `yaml:"thu"`
	Friday    *day `yaml:"fri"`
	Saturday  *day `yaml:"sat"`

	// TimeZone is the local time zone.
	TimeZone string `yaml:"time_zone"`
}

// day is a range within a single day.  Start and End are durations from the
// start of day, with 0s being (0 minutes) and 23h59m (1439 minutes).
type day struct {
	Start timeutil.Duration `yaml:"start"`
	End   timeutil.Duration `yaml:"end"`
}

// BlockedServices is the configuration of blocked services.
type BlockedServices struct {
	// Schedule is blocked services schedule for every day of the week.
	Schedule *BlockedSchedule

	// IDs is the names of blocked services.
	IDs []string `yaml:"ids"`
}

// BlockedSchedule is the internal structure of blocked schedule.
type BlockedSchedule struct {
	// Location contains the local time zone.
	Location *time.Location

	// Week is blocked services schedule for every day of the week.
	Week [7]dayRange
}

// type check
var _ yaml.Unmarshaler = (*BlockedSchedule)(nil)

// UnmarshalYAML implements the [yaml.Unmarshaler] interface for
// *BlockedServices.
func (s *BlockedSchedule) UnmarshalYAML(value *yaml.Node) (err error) {
	conf := &blockedScheduleConfig{}

	err = value.Decode(conf)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	bs := BlockedSchedule{}

	bs.Location, err = time.LoadLocation(conf.TimeZone)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	days := []*day{
		conf.Sunday,
		conf.Monday,
		conf.Tuesday,
		conf.Wednesday,
		conf.Thursday,
		conf.Friday,
		conf.Saturday,
	}
	for i, d := range days {
		if d == nil {
			bs.Week[i] = dayRange{}

			continue
		}

		r := dayRange{
			start: d.Start.Duration,
			end:   d.End.Duration,
		}

		err = r.validate()
		if err != nil {
			return fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
		}

		bs.Week[i] = r
	}

	*s = bs

	return nil
}

// type check
var _ yaml.Marshaler = (*BlockedSchedule)(nil)

// MarshalYAML implements the [yaml.Marshaler] interface for *BlockedServices.
func (s *BlockedSchedule) MarshalYAML() (v any, err error) {
	return blockedScheduleConfig{
		TimeZone: s.Location.String(),
		Sunday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Sunday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Sunday].end},
		},
		Monday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Monday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Monday].end},
		},
		Tuesday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Tuesday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Tuesday].end},
		},
		Wednesday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Wednesday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Wednesday].end},
		},
		Thursday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Thursday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Thursday].end},
		},
		Friday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Friday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Friday].end},
		},
		Saturday: &day{
			Start: timeutil.Duration{Duration: s.Week[time.Saturday].start},
			End:   timeutil.Duration{Duration: s.Week[time.Saturday].end},
		},
	}, nil
}

// Contains returns true if t is within the allowed schedule.
func (s *BlockedSchedule) Contains(t time.Time) (ok bool) {
	t = t.In(s.Location)
	r := s.Week[t.Weekday()]
	if (r == dayRange{}) {
		return false
	}

	mins := time.Duration(60*t.Hour()+t.Minute()) * time.Minute

	return mins >= r.start && mins <= r.end
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

	if !bsvc.Schedule.Contains(time.Now()) {
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
	list := d.Config.BlockedServices.IDs
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
