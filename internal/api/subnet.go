package api

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/tessera/tessera/internal/collector/active"
	"github.com/tessera/tessera/internal/entity"
)

// AddrCell is one address in a subnet's map: its state and (if any) the host
// that holds it.
type AddrCell struct {
	IP       string `json:"ip"`
	State    string `json:"state"` // active | stale | reserved | free
	DHCP     string `json:"dhcp,omitempty"` // reserved | dynamic (DHCP server lease class)
	Host     string `json:"host,omitempty"`
	StableID string `json:"stable_id,omitempty"`
}

// SubnetDetail is the address map + utilization for one subnet.
type SubnetDetail struct {
	Subnet      entity.Subnet `json:"subnet"`
	Addresses   []AddrCell    `json:"addresses"`
	Total       int           `json:"total"`
	Used        int           `json:"used"`
	Free        int           `json:"free"`
	Utilization int           `json:"utilization"` // percent used
	NextFree    string        `json:"next_free,omitempty"`
	FullMap     bool          `json:"full_map"` // false when the range is too large to enumerate
}

// handleSubnet returns a single subnet's address map. IPv4 ranges up to the
// prober's enumeration cap get a full cell-per-address map (free addresses
// included); larger ranges / IPv6 fall back to just the observed addresses.
func (s *Server) handleSubnet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing or bad id")
		return
	}
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var sn *entity.Subnet
	for i := range snap.Subnets {
		if snap.Subnets[i].ID == id {
			sn = &snap.Subnets[i]
			break
		}
	}
	if sn == nil {
		writeErr(w, http.StatusNotFound, "subnet not found")
		return
	}

	name := map[int64]string{}
	stable := map[int64]string{}
	for _, h := range snap.Hosts {
		name[h.ID], stable[h.ID] = h.DisplayName, h.StableID
	}
	observed := map[string]entity.Address{}
	for _, a := range snap.Addresses {
		if a.SubnetID != nil && *a.SubnetID == id {
			observed[a.IP] = a
		}
	}
	cellFor := func(ip string, a entity.Address, free bool) AddrCell {
		c := AddrCell{IP: ip, State: "free"}
		if !free {
			c.State = string(a.State)
			c.DHCP = a.DHCP
			if a.HostID != nil {
				c.Host, c.StableID = name[*a.HostID], stable[*a.HostID]
			}
		}
		return c
	}

	out := SubnetDetail{Subnet: *sn}
	targets, skipped, err := active.EnumerateTargets([]string{sn.CIDR})
	out.FullMap = err == nil && len(skipped) == 0 && len(targets) > 0

	if out.FullMap {
		for _, ip := range targets {
			s := ip.String()
			if a, ok := observed[s]; ok {
				out.Addresses = append(out.Addresses, cellFor(s, a, false))
			} else {
				out.Addresses = append(out.Addresses, cellFor(s, entity.Address{}, true))
			}
		}
		out.Total = len(out.Addresses)
		for _, c := range out.Addresses {
			if c.State == "free" {
				if out.NextFree == "" {
					out.NextFree = c.IP
				}
			} else {
				out.Used++
			}
		}
		out.Free = out.Total - out.Used
		if out.Total > 0 {
			out.Utilization = out.Used * 100 / out.Total
		}
	} else {
		// Too large / IPv6: show observed addresses only, sorted.
		ips := make([]string, 0, len(observed))
		for ip := range observed {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips {
			out.Addresses = append(out.Addresses, cellFor(ip, observed[ip], false))
		}
		out.Used = len(out.Addresses)
		out.Total = out.Used
	}
	writeJSON(w, http.StatusOK, out)
}
