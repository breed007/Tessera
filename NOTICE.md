# Third-party notices

Tessera itself is MIT licensed — see [LICENSE](LICENSE).

This file covers material Tessera **redistributes**: data files compiled into
the binary via `go:embed`, and the Go modules it builds against.

---

## ⚠️ Unverified entries

Four bundled data files carry a `**LICENSE: UNVERIFIED**` marker below. Their
*provenance* is known and recorded — each one's origin has been tracked in the
source since it was added — but the *terms* under which they may be
redistributed have not been confirmed with the upstream source.

**This is a known gap, stated openly rather than papered over.** Anyone
redistributing Tessera, packaging it, or vendoring these files should resolve
the marked entries first. Contributions that replace an `UNVERIFIED` marker with
a confirmed license (and a link to where it is stated) are welcome.

The files are separable: each is loaded by one collector and can be replaced or
removed without touching the identification engine.

---

## Bundled data files

### `internal/collector/passive/apple_models.json`

- **Contents:** 1,239 Apple model identifiers and board IDs → marketing names
  (`Mac16,7` → "MacBook Pro (16-inch, M4 Pro, Nov 2024)").
- **Source:** AppleDB — <https://appledb.dev> (`api.appledb.dev/device/main.json`)
- **Upstream project:** <https://github.com/littlebyteorg/appledb>
- **LICENSE: UNVERIFIED** — <!-- TODO: confirm AppleDB's terms and record them here.
  Check the upstream repository's LICENSE file and any terms stated on appledb.dev. -->
- **Used by:** `internal/collector/passive/apple_models.go`

### `internal/collector/unifi/fingerprint_devices.json`

- **Contents:** ~5,572 UniFi `dev_id` → device model names.
- **Source:** UniFi-Icon-Browser — <https://github.com/CANTI-BOT/UniFi-Icon-Browser>
  (`chrome-extension/data`)
- **LICENSE: UNVERIFIED** — <!-- TODO: this is the entry to resolve FIRST. The data is
  derived from Ubiquiti's own device-fingerprint database, so two sets of terms may
  apply: the intermediate project's, and Ubiquiti's. Confirm both. -->
- **Used by:** `internal/collector/unifi/fpdb.go`

### `internal/collector/unifi/unifi_models.json`

- **Contents:** UniFi model codes → product names (`U7PG2` → "UAP AC Pro").
- **Source:** public gist `sgrodzicki/265273ff0ede952d6fcd1a1eedb6aa60`
- **LICENSE: UNVERIFIED** — <!-- TODO: GitHub gists frequently carry no license at all,
  which means all rights reserved by default. Confirm, or replace this file with data
  from a clearly-licensed source. -->
- **Used by:** `internal/collector/unifi/fpdb.go`

### `internal/collector/unifi/unifi_ports.json`

- **Contents:** 171 UniFi models → physical port counts, for the patch-panel view.
- **Source:** Ubiquiti `public.json`
- **LICENSE: UNVERIFIED** — <!-- TODO: Ubiquiti's data. Confirm their terms for
  redistribution of the public device manifest. -->
- **Used by:** `internal/collector/unifi/fpdb.go`

---

## Device icons

Icons served by the web UI are original SVGs, or drawn from Simple Icons
(<https://simpleicons.org>), which is released under **CC0 1.0 Universal**
(public domain dedication).

Tessera bundles no vendor product photography and no copyrighted device imagery.
Operator-uploaded custom icons are the operator's own material and are stored
outside the repository.

---

## Go module dependencies

Fetched at build time rather than vendored — not redistributed in source form,
but statically linked into the released binaries. Each is used under its own
license; see each project for the authoritative text.

### Direct

| Module | Purpose |
|---|---|
| `github.com/gopacket/gopacket` | packet decoding for the passive sensor (`-tags pcap` builds only) |
| `golang.org/x/crypto` | password hashing for local accounts |
| `golang.org/x/net` | DNS message encoding for the active mDNS querier |
| `golang.org/x/term` | terminal handling in the CLI |
| `gopkg.in/yaml.v3` | configuration file parsing |
| `howett.net/plist` | Apple property-list parsing (AirPlay `/info`) |
| `modernc.org/sqlite` | pure-Go SQLite driver — the reason the binary is CGO-free |

### Indirect

`github.com/dustin/go-humanize`, `github.com/google/uuid`,
`github.com/mattn/go-isatty`, `github.com/ncruces/go-strftime`,
`github.com/remyoudompheng/bigfft`, `golang.org/x/sys`, `modernc.org/libc`,
`modernc.org/mathutil`, `modernc.org/memory`.

Run `go list -m -json all` for exact versions, or read `go.mod` / `go.sum`.

---

## Protocol references

The identification probes implement publicly documented protocols. No
proprietary specification is reproduced here; these are cited so a reader can
check the implementation against the source of truth.

- **NTLM / NTLMSSP** — [MS-NLMP], Microsoft Open Specifications.
- **SMB2** — [MS-SMB2], Microsoft Open Specifications.
- **RDP / CredSSP** — [MS-RDPBCGR], [MS-CSSP], Microsoft Open Specifications.
- **SPNEGO** — RFC 4178.
- **mDNS / DNS-SD** — RFC 6762, RFC 6763.
- **SSDP / UPnP** — UPnP Device Architecture.
- **DHCP** — RFC 2131, RFC 2132 (options 55 and 60).
- **SNMP** — RFC 1157, RFC 3411.
- **Server-Sent Events** — WHATWG HTML Living Standard (ESPHome `/events`).
