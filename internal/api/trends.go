package api

import (
	"net/http"
	"sort"
	"time"
)

// TimePoint is one (time, value) sample for a trend line.
type TimePoint struct {
	T time.Time `json:"t"`
	V int       `json:"v"`
}

// SubnetUtil is current per-subnet utilization for the dashboard bar chart.
type SubnetUtil struct {
	CIDR        string  `json:"cidr"`
	Name        string  `json:"name,omitempty"`
	Used        int     `json:"used"`
	Total       int     `json:"total"`
	Utilization float64 `json:"utilization"` // 0–1, IPv4
}

// TrendsView is the dashboard's time-series payload.
type TrendsView struct {
	DeviceGrowth []TimePoint  `json:"device_growth"` // cumulative known devices, by day
	Availability []TimePoint  `json:"availability"`  // network-wide online count over time
	Subnets      []SubnetUtil `json:"subnets"`       // current utilization per subnet
}

func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := TrendsView{DeviceGrowth: []TimePoint{}, Availability: []TimePoint{}, Subnets: []SubnetUtil{}}

	// Device growth: cumulative count of hosts by the day they were first seen.
	days := map[string]int{}
	order := []string{}
	for _, h := range snap.Hosts {
		if h.FirstSeen.IsZero() {
			continue
		}
		key := h.FirstSeen.UTC().Format("2006-01-02")
		if _, ok := days[key]; !ok {
			order = append(order, key)
		}
		days[key]++
	}
	sort.Strings(order)
	cum := 0
	for _, k := range order {
		cum += days[k]
		t, _ := time.Parse("2006-01-02", k)
		out.DeviceGrowth = append(out.DeviceGrowth, TimePoint{T: t, V: cum})
	}

	// Availability: replay every transition, tracking per-host online state, and
	// emit the total online count after the last transition at each timestamp.
	if evs, err := s.store.AllAvailability(ctx); err == nil {
		state := map[string]bool{}
		online := 0
		for i, e := range evs {
			if e.Online && !state[e.StableID] {
				online++
			} else if !e.Online && state[e.StableID] {
				online--
			}
			state[e.StableID] = e.Online
			if i == len(evs)-1 || !evs[i+1].At.Equal(e.At) {
				out.Availability = append(out.Availability, TimePoint{T: e.At, V: online})
			}
		}
	}

	// Subnet utilization (current snapshot).
	usedBySubnet := map[int64]int{}
	for _, a := range snap.Addresses {
		if a.SubnetID != nil {
			usedBySubnet[*a.SubnetID]++
		}
	}
	for _, sn := range snap.Subnets {
		u := SubnetUtil{CIDR: sn.CIDR, Name: sn.Name, Used: usedBySubnet[sn.ID]}
		if total := usableIPv4(sn.CIDR); total > 0 {
			u.Total = total
			u.Utilization = float64(u.Used) / float64(total)
		}
		out.Subnets = append(out.Subnets, u)
	}
	sort.Slice(out.Subnets, func(i, j int) bool { return out.Subnets[i].Utilization > out.Subnets[j].Utilization })

	writeJSON(w, http.StatusOK, out)
}
