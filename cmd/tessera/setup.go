package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/tessera/tessera/internal/secret"
)

// cmdSetup is the guided installer (§M9). It introspects the host's interfaces,
// asks a handful of questions (or takes them as flags for non-interactive use),
// and writes a ready-to-run config + an env file with the admin password hash.
// It is the friendly path to a first run — and to satisfying the LAN-bind auth
// requirement without hand-editing YAML.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/tessera/config.yaml", "config file to write")
	envPath := fs.String("env", "/etc/tessera/tessera.env", "env file to write (secrets)")
	nonInteractive := fs.Bool("non-interactive", false, "don't prompt; use flags and defaults")
	force := fs.Bool("force", false, "overwrite an existing config")
	printOnly := fs.Bool("print", false, "write to stdout instead of files (dry run)")
	port := fs.Int("port", 10404, "API port")
	bind := fs.String("bind", "local", "API bind scope: local | lan")
	adminUser := fs.String("admin-user", "admin", "admin username")
	adminPass := fs.String("admin-password", "", "admin password (omit to be prompted)")
	ifaceName := fs.String("interface", "", "management/egress interface (default: auto-detect)")
	spanNIC := fs.String("span", "", "optional SPAN/tap interface for the passive sensor")
	probeSubnet := fs.String("probe-subnet", "", "active-probe subnet CIDR (default: management interface subnet; '-' to disable)")
	unifiURL := fs.String("unifi-url", "", "UniFi controller base URL (optional)")
	tlsFlag := fs.Bool("tls", false, "serve the UI over HTTPS (self-signed)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	preflight()

	nics := enumNICs()
	in := bufio.NewReader(os.Stdin)
	s := setupAnswers{
		Port:      *port,
		AdminUser: *adminUser,
		MgmtIface: *ifaceName,
		SpanNIC:   *spanNIC,
		UnifiURL:  *unifiURL,
		LANBind:   *bind == "lan",
		TLS:       *tlsFlag,
		SecretKey: secret.GenerateKey(),
	}

	if *nonInteractive {
		s.AdminPass = *adminPass
		if s.MgmtIface == "" {
			s.MgmtIface = defaultIface(nics)
		}
		s.ProbeSubnet = resolveProbeSubnet(*probeSubnet, s.MgmtIface, nics)
	} else {
		askInteractive(&s, in, nics)
	}

	if s.AdminPass == "" {
		return fmt.Errorf("setup: an admin password is required (use -admin-password or run interactively)")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(s.AdminPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.PassHash = string(hash)
	s.Token = randomToken()
	s.ListenAddr = bindAddr(s.LANBind, s.Port)

	configText, envText := render(s)

	if *printOnly {
		fmt.Println("# ── " + *configPath + " ──")
		fmt.Println(configText)
		fmt.Println("# ── " + *envPath + " (secrets) ──")
		fmt.Println(envText)
		return nil
	}

	if _, err := os.Stat(*configPath); err == nil && !*force {
		return fmt.Errorf("setup: %s already exists (use -force to overwrite)", *configPath)
	}
	if err := writeFileSecure(*configPath, configText, 0o640); err != nil {
		return err
	}
	if err := writeFileSecure(*envPath, envText, 0o640); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nWrote %s and %s\n", *configPath, *envPath)
	fmt.Fprintf(os.Stderr, "Admin user: %s   API token (for scripts): %s\n", s.AdminUser, s.Token)
	fmt.Fprintf(os.Stderr, "Start it:   systemctl restart tessera\n")
	host := "localhost"
	if s.LANBind {
		host = "<this-host-ip>"
	}
	fmt.Fprintf(os.Stderr, "Open:       http://%s:%d  (log in as %s)\n\n", host, s.Port, s.AdminUser)
	return nil
}

type setupAnswers struct {
	Port        int
	LANBind     bool
	ListenAddr  string
	AdminUser   string
	AdminPass   string
	PassHash    string
	Token       string
	MgmtIface   string
	SpanNIC     string
	ProbeSubnet string // "" = disabled
	UnifiURL    string
	TLS         bool
	SecretKey   string
}

func askInteractive(s *setupAnswers, in *bufio.Reader, nics []nic) {
	fmt.Println("Tessera setup — answer a few questions (Enter accepts the [default]).")
	fmt.Println()

	// Management interface.
	def := s.MgmtIface
	if def == "" {
		def = defaultIface(nics)
	}
	fmt.Println("Detected interfaces:")
	for _, n := range nics {
		mark := "  "
		if n.name == def {
			mark = "* "
		}
		fmt.Printf("  %s%-12s %s\n", mark, n.name, n.cidr)
	}
	s.MgmtIface = ask(in, "Management interface (probes egress here)", def)

	// Optional SPAN/tap.
	s.SpanNIC = ask(in, "SPAN/tap interface for passive capture (blank = none)", s.SpanNIC)
	if s.SpanNIC != "" {
		fmt.Println("  note: passive capture needs a -tags pcap build; recorded in config either way.")
	}

	// Port + exposure.
	s.Port = askInt(in, "API port", s.Port)
	s.LANBind = askYesNo(in, "Expose the UI on the LAN (not just localhost)?", s.LANBind)

	// Admin account.
	s.AdminUser = ask(in, "Admin username", s.AdminUser)
	s.AdminPass = askPassword("Admin password")

	// Active probe.
	subnetDef := subnetOf(s.MgmtIface, nics)
	if askYesNo(in, "Actively probe a subnet to discover hosts now?", subnetDef != "") {
		s.ProbeSubnet = ask(in, "  subnet (CIDR)", subnetDef)
	}

	// UniFi (optional).
	if askYesNo(in, "Configure a UniFi controller?", s.UnifiURL != "") {
		s.UnifiURL = ask(in, "  UniFi base URL", s.UnifiURL)
	}

	// TLS (recommended when exposed on the LAN).
	s.TLS = askYesNo(in, "Serve the UI over HTTPS (self-signed certificate)?", s.LANBind)
}

// ── preflight resource check (warn only; never blocks or changes anything) ────

func preflight() {
	const dataDir = "/var/lib/tessera"
	if free, ok := freeDiskBytes(dataDir); ok && free < 2<<30 {
		fmt.Fprintf(os.Stderr, "  ! low free disk: %.1f GB — the observation log grows over time; 8 GB recommended\n",
			float64(free)/(1<<30))
	}
	if avail, ok := availRAMBytes(); ok && avail < 256<<20 {
		fmt.Fprintf(os.Stderr, "  ! low available memory: %d MB — 512 MB recommended\n", avail>>20)
	}
}

// freeDiskBytes returns bytes available on the filesystem holding path (or its
// nearest existing ancestor).
func freeDiskBytes(path string) (uint64, bool) {
	for p := path; p != ""; p = dirOf(p) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err == nil {
			return uint64(st.Bavail) * uint64(st.Bsize), true
		}
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err == nil {
		return uint64(st.Bavail) * uint64(st.Bsize), true
	}
	return 0, false
}

// availRAMBytes reads MemAvailable from /proc/meminfo (Linux only; returns false
// elsewhere, so the check is simply skipped).
func availRAMBytes() (uint64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			f := strings.Fields(rest) // ["123456", "kB"]
			if len(f) >= 1 {
				if kb, err := strconv.ParseUint(f[0], 10, 64); err == nil {
					return kb * 1024, true
				}
			}
		}
	}
	return 0, false
}

// ── interface introspection ──────────────────────────────────────────────────

type nic struct {
	name string
	ipv4 string
	cidr string
}

func enumNICs() []nic {
	var out []nic
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			out = append(out, nic{name: ifi.Name, ipv4: ipnet.IP.String(), cidr: ipnet.String()})
			break
		}
	}
	return out
}

// defaultIface finds the interface that owns the default-route source IP (the
// UDP-dial trick sends no packet — it only triggers a route lookup).
func defaultIface(nics []nic) string {
	c, err := net.Dial("udp4", "8.8.8.8:80")
	if err == nil {
		defer c.Close()
		src := c.LocalAddr().(*net.UDPAddr).IP.String()
		for _, n := range nics {
			if n.ipv4 == src {
				return n.name
			}
		}
	}
	if len(nics) > 0 {
		return nics[0].name
	}
	return "eth0"
}

func subnetOf(name string, nics []nic) string {
	for _, n := range nics {
		if n.name == name {
			if _, ipnet, err := net.ParseCIDR(n.cidr); err == nil {
				return ipnet.String() // network/prefix, e.g. 10.0.0.0/24
			}
		}
	}
	return ""
}

func resolveProbeSubnet(flagVal, iface string, nics []nic) string {
	switch flagVal {
	case "-":
		return ""
	case "":
		return subnetOf(iface, nics)
	default:
		return flagVal
	}
}

func bindAddr(lan bool, port int) string {
	if lan {
		return "0.0.0.0:" + strconv.Itoa(port)
	}
	return "127.0.0.1:" + strconv.Itoa(port)
}

// ── prompts ──────────────────────────────────────────────────────────────────

func ask(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askInt(in *bufio.Reader, label string, def int) int {
	v := ask(in, label, strconv.Itoa(def))
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func askYesNo(in *bufio.Reader, label string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	fmt.Printf("%s [%s]: ", label, d)
	line, _ := in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return def
	}
}

func askPassword(label string) string {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-TTY (piped) — read a plain line.
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimSpace(line)
	}
	for {
		fmt.Printf("%s: ", label)
		b1, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		fmt.Printf("%s (again): ", label)
		b2, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if string(b1) == string(b2) && len(b1) > 0 {
			return string(b1)
		}
		fmt.Println("  passwords didn't match (or were empty) — try again")
	}
}

// ── output ───────────────────────────────────────────────────────────────────

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeFileSecure(path, content string, mode os.FileMode) error {
	if dir := dirOf(path); dir != "" {
		_ = os.MkdirAll(dir, 0o750)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("setup: write %s: %w", path, err)
	}
	// Best-effort: root:tessera ownership so the service can read it.
	if u, err := user.Lookup("tessera"); err == nil {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			_ = os.Chown(path, 0, gid) // root owner, tessera group
		}
	}
	return nil
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return ""
}

func render(s setupAnswers) (configText, envText string) {
	var cfg strings.Builder
	_ = configTmpl.Execute(&cfg, s)

	var env strings.Builder
	env.WriteString("# Tessera secrets — read by the systemd unit (EnvironmentFile).\n")
	env.WriteString("# Keep this file root:tessera 0640. Never commit it.\n")
	env.WriteString("TESSERA_API_PASSWORD_HASH=" + s.PassHash + "\n")
	env.WriteString("TESSERA_API_TOKEN=" + s.Token + "\n")
	env.WriteString("TESSERA_SECRET_KEY=" + s.SecretKey + "  # master key for settings secrets — back this up; losing it makes stored secrets unrecoverable\n")
	if s.UnifiURL != "" {
		env.WriteString("# TESSERA_UNIFI_USERNAME=tessera-ro\n")
		env.WriteString("# TESSERA_UNIFI_PASSWORD=\n")
	}
	return cfg.String(), env.String()
}

var configTmpl = template.Must(template.New("cfg").Parse(`# Tessera configuration — generated by 'tessera setup'.
sensor:
{{- if .SpanNIC}}
  enabled: true
  sources:
    - kind: span
      nic: {{.SpanNIC}}
{{- else}}
  enabled: false
{{- end}}
  dedupe_window_ms: 50

active_probe:
{{- if .ProbeSubnet}}
  enabled: true
  subnets: [{{.ProbeSubnet}}]
  interface: {{.MgmtIface}}
  icmp: true
  tcp_ports: [22, 80, 443, 445, 3389, 161]
  udp_ports: [5353, 1900]   # mDNS (Bonjour) + SSDP — liveness for TVs/speakers/IoT
  rate:
    max_probes_per_sec: 20
    cycle_interval: 15m
{{- else}}
  enabled: false
  subnets: []
{{- end}}

unifi:
{{- if .UnifiURL}}
  enabled: true
  base_url: {{.UnifiURL}}
  path_prefix: /proxy/network
  site: default
  verify_tls: false
  poll_interval: 5m
{{- else}}
  enabled: false
{{- end}}

fingerbank:
  enabled: false
  mode: api

reconcile:
  stale_after: 24h
  free_after: 168h
  confidence_half_life: 72h

storage:
  driver: sqlite
  dsn: /var/lib/tessera/tessera.db

api:
  enabled: true
  listen_addr: {{.ListenAddr}}
  auth_user: {{.AdminUser}}
  tls: {{.TLS}}
  # Admin password hash, API token, and secret key are in the env file.
`))
