package api

import (
	"net/http"
	"sort"
	"strings"
)

// ServiceRow is one discovered service, enriched with the owning host's name and
// a friendly service name derived from the port.
type ServiceRow struct {
	Service  string `json:"service"` // "HTTPS", "SSH", … or "" for an unnamed port
	Proto    string `json:"proto"`
	Port     int    `json:"port"`
	Host     string `json:"host"`
	HostID   *int64 `json:"host_id,omitempty"`
	StableID string `json:"stable_id,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// handleServices returns discovered services, sorted by friendly service name
// (alphabetical), with unnamed numeric ports last (by port number) — the order
// the UI renders top to bottom.
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := map[int64]string{}
	stable := map[int64]string{}
	for _, h := range snap.Hosts {
		name[h.ID] = h.DisplayName
		stable[h.ID] = h.StableID
	}
	rows := make([]ServiceRow, 0, len(snap.Services))
	for _, sv := range snap.Services {
		row := ServiceRow{
			Service: servicePortName(sv.Proto, sv.Port),
			Proto:   sv.Proto, Port: sv.Port, Banner: sv.Banner, HostID: sv.HostID,
		}
		if sv.HostID != nil {
			row.Host = name[*sv.HostID]
			row.StableID = stable[*sv.HostID]
		}
		rows = append(rows, row)
	}
	// Named services alphabetically; unnamed (numeric-only) ports after them by
	// port number. Ties broken by host then port for stable output.
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		an, bn := a.Service != "", b.Service != ""
		if an != bn {
			return an // named first
		}
		if an {
			if !strings.EqualFold(a.Service, b.Service) {
				return strings.ToLower(a.Service) < strings.ToLower(b.Service)
			}
		} else if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
	writeJSON(w, http.StatusOK, rows)
}

// servicePortName maps a well-known port to a friendly service name, or "" if the
// port has no common name (the UI shows it as a bare numeric port).
func servicePortName(proto string, port int) string {
	if n, ok := commonPorts[port]; ok {
		return n
	}
	return ""
}

// commonPorts is a curated set of well-known service names keyed by port. Kept
// deliberately small and recognizable; unknown ports render as the number.
var commonPorts = map[int]string{
	20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
	111: "RPC", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS",
	139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS",
	445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "Printer (LPD)", 548: "AFP",
	554: "RTSP", 587: "SMTP", 631: "IPP", 636: "LDAPS", 873: "rsync", 989: "FTPS",
	990: "FTPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
	1521: "Oracle", 1883: "MQTT", 1900: "SSDP", 2049: "NFS", 2375: "Docker",
	2376: "Docker", 3000: "HTTP (dev)", 3128: "Proxy", 3306: "MySQL", 3389: "RDP",
	5000: "UPnP/HTTP", 5001: "HTTP-alt", 5060: "SIP", 5061: "SIP-TLS", 5353: "mDNS",
	5432: "PostgreSQL", 5683: "CoAP", 5900: "VNC", 6379: "Redis", 8006: "Proxmox",
	8080: "HTTP (alt)", 8083: "HTTP (alt)", 8123: "Home Assistant", 8443: "HTTPS (alt)",
	8554: "RTSP", 8883: "MQTTS", 9000: "HTTP (alt)", 9090: "HTTP (alt)", 9100: "JetDirect",
	9200: "Elasticsearch", 27017: "MongoDB", 32400: "Plex", 37777: "Dahua DVR", 51820: "WireGuard",
}
