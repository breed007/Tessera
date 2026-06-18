// Package portrisk classifies a reachable TCP/UDP port into a security-review
// finding (plaintext, remote-access, exposed database, file sharing, …). It's
// pure and dependency-free so both the Security page (api) and the alert engine
// can share one source of truth. These are services worth confirming are
// intentional on a LAN — not confirmed vulnerabilities.
package portrisk

// Risk describes why a reachable port is worth a look.
type Risk struct {
	Severity string // high | medium | low
	Category string
	Title    string
	Why      string
}

// Classify returns the risk for a port, or ok=false if it isn't notable
// (SSH/HTTPS/DNS and other normal services aren't flagged, to limit noise).
func Classify(port int) (Risk, bool) {
	if r, ok := table[port]; ok {
		return r, true
	}
	switch {
	case port >= 5900 && port <= 5905:
		return Risk{"high", "remote-access", "VNC exposed", "VNC remote desktop — often weak or no authentication"}, true
	case port >= 512 && port <= 514:
		return Risk{"medium", "legacy", "r-services exposed", "rexec/rlogin/rsh — legacy, plaintext"}, true
	}
	return Risk{}, false
}

var table = map[int]Risk{
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
