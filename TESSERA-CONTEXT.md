# Tessera — context handoff (for device / OS identification work)

**What this is:** a briefing for a fresh session that will work on **device
classification and OS identification**. It summarizes the whole project, then
goes deep on the identification subsystem — where it lives, how confidence
works, what's bundled, and where the real seams are.

**State as of this doc:** v1.0.0, 18 migrations, all tests green.
Last commit: `313fe45`.

---

## 1. What Tessera is

A **discovery-first IPAM** for homelab/SMB networks, written in Go. Instead of
asking you to type your network into a database (NetBox's model), it *discovers*
what's there and reconciles conflicting evidence into an inventory.

The core architectural rule:

```
collectors → append-only observation log → reconciliation → entity layer → API/UI
```

Nothing writes entities directly. Every fact enters as an **observation**
(`source`, `subject`, `attribute`, `value`, `confidence`, `observed_at`), and
the reconciler rebuilds the entity layer from that log. This means the inventory
is always reconstructable by replaying the log from empty — and it's why every
classification decision is auditable back to its evidence.

**Strategic position:** Tessera is the *engine + API*. CableMap (physical layer)
and a runbook generator consume its `/api/v1` surface. Keep them decoupled.

### Stack
- Go, single binary, `CGO_ENABLED=0` by default
- SQLite (`internal/store/sqlite`), forward-only migrations
- Vanilla-JS UI, no build step, `go:embed`'d (`internal/web/assets/`)
- Packaged as `.deb`/`.rpm`/`.apk` via goreleaser

### Build / run / test
```bash
go build ./...                              # build
go test ./...                               # full suite
go vet ./...                                # vet
node --check internal/web/assets/app.js     # UI syntax (no build step, so check it)
goreleaser release --snapshot --clean       # packages into dist/

# run locally
go build -o /tmp/tessera ./cmd/tessera
TESSERA_SECRET_KEY=$(openssl rand -hex 32) /tmp/tessera run -config <cfg>.yaml
```

**Validation cadence used throughout this project:** `go build ./...` →
`node --check app.js` → `go vet ./...` → `go test ./...`. Run all four before
committing.

**Note on the passive sensor:** libpcap/cgo is isolated behind a `pcap` build
tag (`internal/collector/passive/capture_pcap.go`, with `capture_stub.go` for
the default build). `go build` works without libpcap; `go build -tags pcap`
enables live capture. **The shipped .deb is pure-Go, so passive capture is OFF
in released builds.** That matters a lot for identification work — see §5.

---

## 2. Key packages (identification-relevant)

| Path | Role |
|---|---|
| `internal/observation/` | Observation type, valid **sources** + **attributes**, the `Sink` every collector writes through |
| `internal/reconcile/` | `engine.go` (fold observations → entities), `score.go` (confidence/winner), `inference.go` (**the generic inference layer**), `tiers.go` (source tiers) |
| `internal/collector/passive/` | pcap parsers: ARP/NDP, DHCPv4/v6, **mDNS**, SSDP, NetBIOS. Holds `apple_models.json` |
| `internal/collector/active/` | Scoped prober: ICMP/TCP/UDP, banners, rDNS, SNMP, **active mDNS**, **AirPlay/Cast media probes**, TCP-behavioral |
| `internal/collector/unifi/` | Controller poller. Holds `fingerprint_devices.json`, `unifi_models.json` |
| `internal/collector/fingerbank/` | Optional third-party DHCP-fingerprint enrichment (**off by default**, privacy) |
| `internal/collector/proxmox/` | VM/CT inventory (up to 5 instances) |
| `internal/collector/dns/`, `dhcp/` | Name/lease ingestion (hosts files, Unbound, AdGuard/Pi-hole/Technitium) |
| `internal/icons/` | `Auto(vendor, os, deviceClass, model) → icon id` — brand/type icon selection |
| `internal/netid/` | MAC/IP normalization + **MAC-randomization detection** (locally-administered bit) |

---

## 3. The identification subsystem (the main event)

### 3.1 Attributes that carry identity

From `internal/observation/observation.go`:

- `device_class` — what kind of thing it is ("computer", "printer", …)
- `os_guess` — operating system
- `model` — precise hardware model (e.g. `MacBook Pro (16-inch, M4 Pro, Nov 2024)`)
- `oui_vendor`, `dhcp_fingerprint`, `dhcp_vendor`, `hostname`, `service_banner`,
  `open_port`, `tcp_behavior`, `user_agent`

### 3.2 Signal sources, by strength

Every emitter attaches a confidence. The reconciler picks a winner by
**effective confidence** (confidence decayed by recency), with source tier only
as a tiebreak, and manual annotations always authoritative.

| Confidence | Signal | Where |
|---|---|---|
| **88** | **mDNS `model=` exact match** → precise marketing name via Apple table | `passive/parse.go`, `active/emit.go` |
| 85 | UniFi controller gear model | `unifi/mapping.go` |
| 82 | Media probe model (AirPlay `/info`, Cast `eureka_info`) | `active/emit.go` |
| 78 / 76 | Media probe device class / OS | `active/emit.go` |
| 75 | UniFi client fingerprint device class | `unifi/mapping.go` |
| 70 | mDNS `model=` **generic** family match; UniFi fingerprint OS; SNMP sysDescr | various |
| 55 / 50 | mDNS service-type class / OS (`_airplay` → media device) | `parse.go`, `emit.go` |
| 50 | SSDP class | `passive/parse.go` |
| 30–80 | **Generic inference** (see §3.4) | `reconcile/inference.go` |
| 30 | TCP behavioral fingerprint (deliberately weak) | `active/emit.go` |
| API score | Fingerbank verdict (clamped) | `fingerbank/` |

**Design intent worth preserving:** a device's *self-report* (mDNS `model=` at
88) deliberately outranks a *vendor's guess about it* (UniFi fingerprint at 75).
That's why a MacBook shows its real model instead of UniFi's stale guess.

### 3.3 Bundled lookup tables (all refreshable by replacing the file)

| File | Size | Contents | Source |
|---|---|---|---|
| `passive/apple_models.json` | 55 KB | 1,239 keys: Apple model identifiers **and board IDs** → exact marketing name (`Mac16,7` → "MacBook Pro (16-inch, M4 Pro, Nov 2024)") | AppleDB |
| `unifi/fingerprint_devices.json` | 180 KB | ~5,572 `dev_id` → model | UniFi-Icon-Browser |
| `unifi/unifi_models.json` | 50 KB | 167 model-code → name (`U7PG2` → "UAP AC Pro") | public gist |
| `unifi/unifi_ports.json` | 2.6 KB | 171 model → port count (for the patch-panel view) | UniFi public.json |

### 3.4 The generic inference layer — read this before changing anything

`internal/reconcile/inference.go` (405 lines) is the last-pass classifier. It
combines weak-but-cheap signals and **votes**:

```go
type inferInput struct {
    openPorts   []int
    banners     []string
    vendor      string   // OUI
    hostname    string
    dhcpVendor  string   // DHCP option 60, e.g. "android-dhcp-13", "MSFT 5.0"
    tcpBehavior string   // rst_immediate | silent_drop | icmp_unreachable
}
```

**Confidence is provenance-based, not weight-based** — it scales with how many
*independent signal categories* agree (`catPort`, `catVendor`, `catHostname`,
`catBanner`, `catDHCPVendor`, `catTCP`):

```go
func voteConfidence(categories, weight int) int {
    case categories >= 3:              return 80  // three independent signals → high
    case categories == 2 && weight >= 4: return 72
    case categories == 2:              return 60
    case weight >= 2:                  return 45
    default:                           return 30  // one weak signal → low
}
```

**⚠️ The critical rule — inference only fills gaps.** In
`reconcile/engine.go` (~line 532) it runs *only* when an authoritative collector
left the attribute empty:

```go
if host.DeviceClass == "" || host.OSGuess == "" {
    res := inferIdentity(...)
    if host.DeviceClass == "" && res.deviceClass != "" { ... }
    if host.OSGuess == "" && res.osGuess != "" { ... }
}
```

This is why inference can safely reach the high confidence band: it can never
override a real classification. **If you change inference to compete with
collectors instead of filling gaps, you break that safety property** — revisit
the confidence ceiling if you do.

Helpers worth knowing: `normalizeHost()` builds a separator-stripped `joined`
string plus a token set, so "Apple TV 4K", "esp32-node-01" and "studiombp14"
all match; `applyAppleFamily()` resolves Apple sub-families; `classifyDHCPVendor()`
maps option-60 strings.

### 3.5 Device-class vocabulary (currently emitted, by frequency)

```
media / TV device (22)   computer (19)      camera (16)      NAS (13)
IoT device (12)          speaker (11)       printer (11)     Apple mobile device (11)
server (7)               switch (4)         router (4)       firewall (4)
tablet (2)               smart display (2)  phone (2)        access point (2)
Virtual Machine (2)      Container (2)      smartwatch (1)
```

**This vocabulary is a convention, not an enum** — it's free-text strings
scattered across collectors. There is no central definition. See §5.

---

## 4. What already works well

- **Apple devices** are excellent — exact marketing names via mDNS `model=` +
  the AppleDB table, plus AirPlay `/info` probes.
- **UniFi gear** resolves to real model names (`UDMPRO` → "UDM Pro").
- **Media/streaming devices** — Fire TV, Apple TV, Chromecast, Nest, Ring, Echo
  — via the active mDNS service-type catalog and AirPlay/Cast HTTP probes
  (`active/mdns.go`, `active/media.go`). These are SPAN-free (direct unicast).
- **Proxmox guests** get named/classified from the hypervisor.
- **Randomized MACs** are detected (`internal/netid`) and de-weighted.

---

## 5. Known gaps & improvement opportunities (honest, ranked)

These are real, verified gaps — good starting points for the next session.

1. **Declared-but-unwired signals.** `AttrUserAgent` and `SourcePassiveTLS`
   (TLS SNI) are defined in `observation.go`, but **nothing ever emits them**.
   Fingerbank only *reads* `user_agent` as an input. So: no HTTP User-Agent
   harvesting, and no TLS SNI/JA3-style fingerprinting exists despite the source
   being reserved. Wiring either would add a strong, cheap signal — especially
   for phones/tablets that say little else.

2. **Non-Apple devices have no exact-model table.** `apple_models.json` gives
   Apple precise names; Android/Windows/Linux/IoT have *nothing* equivalent.
   A Samsung phone or a Windows laptop lands on generic classes. Candidate
   sources to evaluate: Fingerbank's local DB, `hostapd`/DHCP fingerprint
   corpora, or MAC-OUI→product mappings.

3. **The passive sensor is off in shipped builds** (pure-Go `.deb`, no pcap).
   That means DHCP fingerprints and passive mDNS — two of the strongest signals
   — are unavailable to most installs unless the operator builds with `-tags
   pcap` and wires a SPAN port. **The active mDNS querier partly compensates**,
   but consider what else can move from passive → active.

4. **Device-class vocabulary is uncontrolled free text.** The same concept can
   be spelled differently by different collectors, and nothing validates it.
   Introducing a canonical vocabulary (constants + a normalizer at the fold
   step) would improve grouping, icons, and filtering — and is a prerequisite
   for good per-class reporting.

5. **OS strings are inconsistent in shape.** Some are bare (`"iOS"`), some
   versioned (`"iOS 18.3.1"`, from AirPlay), some are raw SNMP `sysDescr` dumps
   (verbose, 70 conf). No normalization or version extraction exists.

6. **Fingerbank is off by default** (privacy: it sends DHCP fingerprints to a
   third party). The `local_db` mode exists and is offline — under-exploited.

7. **No confidence feedback loop.** When an operator manually corrects a
   classification, that correction isn't fed back to improve inference. The
   manual annotation wins for that host, but the *rule* that got it wrong is
   never revisited.

---

## 6. Conventions this project holds to

Respect these — they were deliberate decisions, several learned the hard way.

- **Read-only toward the network.** Tessera never writes to devices/controllers.
  No WoL, no config push. Exports are file-based.
- **Absence is never a fact** (§4.2). A timeout/no-response records *nothing*,
  never "device is X".
- **Secrets** come from env or the encrypted settings store (AES-GCM under
  `secret.key`) — never YAML, never logs.
- **IP-safe assets only.** Icons are original SVGs or CC0 Simple Icons. Do not
  bundle vendor product photos or copyrighted device images.
- **Confidence must stay honest.** Don't inflate a number to win a fight; fix
  the ordering or add a source-precedence rule instead.
- **Forward-only migrations** in `internal/store/sqlite/migrations/` (18 so far).
- **Comment the *why*.** The codebase explains non-obvious decisions inline;
  match that density.
- **RBAC:** three roles — `admin` (everything incl. Settings/credentials),
  `operator` (curation only), `viewer` (read-only). Curation writes are audited.

---

## 7. Useful entry points for device/OS work

```
internal/reconcile/inference.go        # the voting classifier — start here
internal/reconcile/engine.go:~532      # the gap-fill call site
internal/collector/passive/parse.go    # mDNS/DHCP/SSDP parsing + classifyMDNS*
internal/collector/passive/apple_models.go
internal/collector/active/mdns.go      # active mDNS service-type catalog
internal/collector/active/media.go     # AirPlay + Google Cast identity probes
internal/collector/unifi/fpdb.go       # UniFi fingerprint/model lookups
internal/icons/icons.go                # class/vendor → icon
internal/observation/observation.go    # attributes + sources (source of truth)
```

Relevant tests to keep green (and extend):
`internal/reconcile/inference_test.go`, `internal/collector/passive/*_test.go`,
`internal/collector/active/{mdns,media}_test.go`, `internal/icons/icons_test.go`.

---

## 8. Suggested opening prompt for the new session

> Read `TESSERA-CONTEXT.md` in the repo root. I want to improve device
> classification and OS identification. Start by reviewing
> `internal/reconcile/inference.go` and the mDNS classification path, then
> propose concrete improvements — I'm particularly interested in [the unwired
> User-Agent/TLS signals | non-Apple exact-model coverage | normalizing the
> device-class vocabulary].
