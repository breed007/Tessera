package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The two measured contrasts: a garage controller and a plain sensor. The mDNS
// board key reads esp32dev on both, so the entity set is the only separator.
const (
	ratgdoStream = `event: ping
data: {"title":"RATGDO Garage Door","comment":"","ota":true}

event: state
data: {"name_id":"binary_sensor/Obstruction","domain":"binary_sensor","id":"x"}

event: state
data: {"name_id":"cover/Motor","domain":"cover","id":"y"}

event: state
data: {"name_id":"binary_sensor/Motion","domain":"binary_sensor","id":"z"}
`
	sensorStream = `event: ping
data: {"title":"Attic Sensor","comment":"","ota":true}

event: state
data: {"name_id":"sensor/Temperature","domain":"sensor","id":"a"}

event: state
data: {"name_id":"sensor/Humidity","domain":"sensor","id":"b"}

event: state
data: {"name_id":"sensor/WiFi Signal","domain":"sensor","id":"c"}
`
)

func TestParseESPHomeEvents(t *testing.T) {
	f := parseESPHomeEvents(strings.NewReader(ratgdoStream))
	if f.title != "RATGDO Garage Door" {
		t.Errorf("title = %q", f.title)
	}
	want := []string{"Obstruction", "Motor", "Motion"}
	if len(f.entities) != len(want) {
		t.Fatalf("entities = %v, want %v", f.entities, want)
	}
	for i, w := range want {
		if f.entities[i] != w {
			t.Errorf("entity[%d] = %q, want %q", i, f.entities[i], w)
		}
	}
}

// The entity set classifies; the title does not. Renaming the device must not
// change the answer.
func TestESPHomeClassFromEntitiesNotTitle(t *testing.T) {
	garage := parseESPHomeEvents(strings.NewReader(ratgdoStream))
	if got := garage.deviceClass(); got != "garage door controller" {
		t.Errorf("garage class = %q", got)
	}
	renamed := parseESPHomeEvents(strings.NewReader(
		strings.Replace(ratgdoStream, "RATGDO Garage Door", "Kitchen Thing", 1)))
	if got := renamed.deviceClass(); got != "garage door controller" {
		t.Errorf("renamed garage class = %q — the title changed the answer", got)
	}

	sensor := parseESPHomeEvents(strings.NewReader(sensorStream))
	if got := sensor.deviceClass(); got != "" {
		t.Errorf("sensor class = %q, want no specific class", got)
	}
	// ...but a device named "garage" with sensor entities must NOT be one.
	misnamed := parseESPHomeEvents(strings.NewReader(
		strings.Replace(sensorStream, "Attic Sensor", "Garage Door Opener", 1)))
	if got := misnamed.deviceClass(); got == "garage door controller" {
		t.Error("a sensor named 'Garage Door Opener' classified as a controller")
	}
}

// One door-ish entity is not a door. Two independent ones are.
func TestESPHomeGarageNeedsTwoSignals(t *testing.T) {
	one := &esphomeFindings{entities: []string{"Motion"}, domains: map[string]bool{}}
	if one.deviceClass() == "garage door controller" {
		t.Error("a lone Motion entity classified as a garage controller")
	}
	two := &esphomeFindings{entities: []string{"Motor", "Obstruction"}, domains: map[string]bool{}}
	if two.deviceClass() != "garage door controller" {
		t.Error("Motor + Obstruction did not classify as a garage controller")
	}
}

// THE FAILURE THAT MATTERS: /events never closes. A device that connects and
// then goes quiet must be abandoned on schedule, not waited on forever.
func TestProbeESPHomeAbandonsASilentStream(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		probeESPHome(context.Background(), strings.TrimPrefix(srv.URL, "http://"), srv.Client())
	}()
	select {
	case <-done:
	case <-time.After(esphomeMaxDuration + 3*time.Second):
		t.Fatal("probe hung on a silent /events stream")
	}
}

// A stream that never stops must not be read without bound.
func TestParseESPHomeEventsIsBounded(t *testing.T) {
	endless := io.LimitReader(&repeatReader{
		chunk: []byte("data: {\"name_id\":\"sensor/X\",\"domain\":\"sensor\"}\n"),
	}, esphomeMaxBytes)
	done := make(chan struct{})
	go func() { defer close(done); parseESPHomeEvents(endless) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parse did not terminate on an endless stream")
	}
}

type repeatReader struct{ chunk []byte }

func (r *repeatReader) Read(p []byte) (int, error) {
	n := copy(p, r.chunk)
	return n, nil
}
