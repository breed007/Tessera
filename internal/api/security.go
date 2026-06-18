package api

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/tessera/tessera/internal/entity"
)

// SecFinding is one exposed-service / posture observation worth an operator's
// attention. Severity drives ordering and the badge colour.
type SecFinding struct {
	Severity string `json:"severity"` // high | medium | low
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	StableID string `json:"stable_id"`
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// SecurityView is the Security page payload: findings (sorted high→low) + counts.
type SecurityView struct {
	Findings []SecFinding `json:"findings"`
	High     int          `json:"high"`
	Medium   int          `json:"medium"`
	Low      int          `json:"low"`
}

// largeAttackSurface flags a host with at least this many reachable services.
const largeAttackSurface = 12

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	host := map[int64]entity.Host{}
	for _, h := range snap.Hosts {
		host[h.ID] = h
	}
	// Primary IP per host (prefer an active address).
	ipOf := map[int64]string{}
	for _, a := range snap.Addresses {
		if a.HostID == nil {
			continue
		}
		if ipOf[*a.HostID] == "" || a.State == entity.StateActive {
			ipOf[*a.HostID] = a.IP
		}
	}

	out := SecurityView{Findings: []SecFinding{}}
	count := map[int64]int{}
	for _, sv := range snap.Services {
		if sv.HostID == nil {
			continue
		}
		h := host[*sv.HostID]
		if h.Ignored {
			continue
		}
		count[*sv.HostID]++
		risk, ok := portRisk(sv.Port)
		if !ok {
			continue
		}
		out.Findings = append(out.Findings, SecFinding{
			Severity: risk.sev, Category: risk.cat, Title: risk.title, Detail: risk.why,
			StableID: h.StableID, Host: hostLabel(h), IP: ipOf[h.ID], Proto: sv.Proto, Port: sv.Port,
		})
	}
	for id, n := range count {
		h := host[id]
		if h.Ignored || n < largeAttackSurface {
			continue
		}
		out.Findings = append(out.Findings, SecFinding{
			Severity: "low", Category: "attack-surface", Title: "Large attack surface",
			Detail: strconv.Itoa(n) + " reachable services on one host", StableID: h.StableID, Host: hostLabel(h), IP: ipOf[id],
		})
	}

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
	for _, f := range out.Findings {
		switch f.Severity {
		case "high":
			out.High++
		case "medium":
			out.Medium++
		default:
			out.Low++
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func hostLabel(h entity.Host) string {
	if h.DisplayName != "" {
		return h.DisplayName
	}
	return h.StableID
}

type risk struct{ sev, cat, title, why string }

// portRisk classifies a reachable port. These are services worth *reviewing* on a
// LAN (plaintext creds, remote-access, exposed databases, file sharing) — not
// necessarily vulnerabilities, but things to confirm are intentional.
func portRisk(port int) (risk, bool) {
	if r, ok := portRiskTable[port]; ok {
		return r, true
	}
	switch {
	case port >= 5900 && port <= 5905:
		return risk{"high", "remote-access", "VNC exposed", "VNC remote desktop — often weak or no authentication"}, true
	case port >= 512 && port <= 514:
		return risk{"medium", "legacy", "r-services exposed", "rexec/rlogin/rsh — legacy, plaintext"}, true
	}
	return risk{}, false
}

var portRiskTable = map[int]risk{
	23:    {"high", "plaintext", "Telnet exposed", "Telnet — credentials and data sent in clear text"},
	21:    {"high", "plaintext", "FTP exposed", "FTP — credentials and data sent in clear text"},
	2375:  {"high", "admin", "Docker API (unencrypted)", "Unauthenticated remote control of the Docker daemon"},
	6379:  {"high", "database", "Redis exposed", "Redis — frequently reachable without authentication"},
	27017: {"high", "database", "MongoDB exposed", "MongoDB — frequently reachable without authentication"},
	9200:  {"high", "database", "Elasticsearch exposed", "Elasticsearch — frequently reachable without authentication"},
	11211: {"high", "database", "Memcached exposed", "Memcached — no authentication; UDP amplification risk"},
	445:   {"high", "file-sharing", "SMB exposed", "SMB file sharing — common lateral-movement target"},
	3389:  {"high", "remote-access", "RDP exposed", "Remote Desktop — frequent brute-force / exploit target"},

	139:  {"medium", "file-sharing", "NetBIOS exposed", "Legacy Windows file/printer sharing"},
	161:  {"medium", "management", "SNMP exposed", "SNMP — often left on a default community string"},
	3306: {"medium", "database", "MySQL exposed", "MySQL/MariaDB reachable on the network"},
	5432: {"medium", "database", "PostgreSQL exposed", "PostgreSQL reachable on the network"},
	1433: {"medium", "database", "MSSQL exposed", "Microsoft SQL Server reachable on the network"},
	1521: {"medium", "database", "Oracle DB exposed", "Oracle database reachable on the network"},
	25:   {"medium", "mail", "SMTP exposed", "SMTP — verify this is not an open relay"},
	389:  {"medium", "directory", "LDAP exposed", "LDAP directory service (cleartext)"},
	873:  {"medium", "file-sharing", "rsync exposed", "rsync daemon reachable on the network"},
	2376: {"medium", "admin", "Docker API (TLS)", "Docker daemon API reachable on the network"},
	5601: {"medium", "admin", "Kibana exposed", "Kibana admin interface reachable"},

	80:   {"low", "plaintext", "Plaintext HTTP", "HTTP — unencrypted web/admin interface"},
	8080: {"low", "plaintext", "Plaintext HTTP", "HTTP-alt — unencrypted web/admin interface"},
	8006: {"low", "admin", "Proxmox admin", "Proxmox VE web admin reachable"},
	631:  {"low", "printing", "Printer admin", "IPP/printer administration reachable"},
}
