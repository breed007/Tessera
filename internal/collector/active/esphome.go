package active

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// ESPHome identity from the /events stream (ported from IP Recon 1.5).
//
// WHY NOT THE WEB PAGE — it carries nothing. Probing two garage controllers and
// a plain sensor on 2026-08-14 showed the ESPHome web root is a BYTE-IDENTICAL
// 38,990-byte bundle on every device: no <title>, no device name, and
// "esphome.io" as the only distinguishing string. The title a browser shows is
// written by JavaScript after load, so it is not in the document and cannot be
// scraped from it.
//
// /events is where the identity lives. It is a Server-Sent Events stream whose
// FIRST message is a ping carrying the device title, followed by one state event
// per exposed entity:
//
//	event: ping
//	data: {"title":"RATGDO Garage Door","comment":"","ota":true,...}
//	event: state
//	data: {"name_id":"binary_sensor/Obstruction","domain":"binary_sensor",...}
//
// Two signals come out, and the SECOND IS THE STRONGER:
//
//   - title — the owner's name for the device. Useful, but user-editable, so it
//     identifies a device that has been named honestly and nothing else.
//   - the ENTITY SET — structural, and not editable without reflashing the
//     firmware. A board exposing Motor + Obstruction + dry contacts is a garage
//     controller whatever it has been renamed to. Measured contrast:
//
//     garage controller  Motion · Obstruction · Motor · Button ·
//     dry contact open / close / light
//     plain sensor       Temperature · Humidity · Heap Free ·
//     WiFi Signal · Uptime
//
// What this does NOT solve: the mDNS `board` key reads `esp32dev` on both,
// because the garage firmware genuinely targets that board. No board-level
// signal can separate them — the difference is what the firmware exposes, which
// is exactly what this reads.
//
// It is also plain unicast HTTP, so unlike mDNS it survives a routed subnet.

// Hard caps. /events NEVER CLOSES — it is a live telemetry stream, so a naive
// read hangs the sweep forever. IP Recon shipped a version that evaluated its
// caps only INSIDE the read loop, which meant a quiet stream blocked
// indefinitely: a device that sends nothing never reaches the check that would
// have stopped waiting for it. The deadline below is therefore enforced by the
// request context, outside the loop, and not only by the byte and entity counts.
const (
	esphomeMaxDuration = 3 * time.Second
	esphomeMaxBytes    = 64 << 10
	esphomeMaxEntities = 64
)

// esphomeFindings is what the stream volunteered.
type esphomeFindings struct {
	title    string   // the ESPHome friendly name, from the ping event
	entities []string // entity names in arrival order
	domains  map[string]bool
}

func (f *esphomeFindings) empty() bool { return f == nil || (f.title == "" && len(f.entities) == 0) }

// deviceClass derives a class from the ENTITY SET, which the owner cannot rename
// away. Returns "" when the entities describe nothing in particular — an ESPHome
// board is an IoT device either way, and the caller says so.
func (f *esphomeFindings) deviceClass() string {
	has := func(needle string) bool {
		for _, n := range f.entities {
			if strings.Contains(strings.ToLower(n), needle) {
				return true
			}
		}
		return false
	}
	// Deliberately requires TWO independent door-specific entities. A single
	// "Motion" is a motion sensor; a single "Button" is a button. Motor plus
	// obstruction-sensing, or a dry-contact pair, is a door opener and very
	// little else.
	score := 0
	for _, needle := range []string{"obstruction", "motor", "dry contact", "door"} {
		if has(needle) {
			score++
		}
	}
	if score >= 2 {
		return "garage door controller"
	}
	if f.domains["climate"] || has("thermostat") {
		return "thermostat"
	}
	if f.domains["light"] && !f.domains["sensor"] {
		return "smart light"
	}
	if f.domains["switch"] && len(f.entities) <= 3 {
		return "smart plug / switch"
	}
	return ""
}

// probeESPHome reads the /events stream far enough to learn the device's title
// and entity set, then disconnects. Read-only: it consumes a telemetry stream
// and never posts a command.
func probeESPHome(ctx context.Context, host string, client *http.Client) *esphomeFindings {
	// The deadline lives on the context so it applies to the connection and the
	// read alike — a device that connects and then says nothing must still be
	// abandoned on schedule.
	ctx, cancel := context.WithTimeout(ctx, esphomeMaxDuration)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/events", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	f := parseESPHomeEvents(io.LimitReader(resp.Body, esphomeMaxBytes))
	if f.empty() {
		return nil
	}
	return f
}

// parseESPHomeEvents reads SSE `data:` lines until the caps are hit or the
// stream ends. Split from the request so the parsing is testable without a
// network, and so the caps are visible in one place.
func parseESPHomeEvents(r io.Reader) *esphomeFindings {
	f := &esphomeFindings{domains: map[string]bool{}}
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var doc struct {
			Title  string `json:"title"`
			NameID string `json:"name_id"`
			Name   string `json:"name"`
			Domain string `json:"domain"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(line[len("data:"):])), &doc) != nil {
			continue
		}
		if doc.Title != "" && f.title == "" {
			f.title = doc.Title
		}
		if doc.Domain != "" {
			f.domains[doc.Domain] = true
		}
		// name_id is "binary_sensor/Obstruction"; the entity name is the tail.
		name := doc.Name
		if i := strings.LastIndex(doc.NameID, "/"); i >= 0 {
			name = doc.NameID[i+1:]
		}
		if name != "" && !seen[name] {
			seen[name] = true
			f.entities = append(f.entities, name)
		}
		// The stream never ends on its own; stop once we have enough to classify.
		if len(f.entities) >= esphomeMaxEntities {
			break
		}
	}
	return f
}
