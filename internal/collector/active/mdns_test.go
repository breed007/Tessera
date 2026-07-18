package active

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBuildMDNSQuery(t *testing.T) {
	pkt, err := buildMDNSQuery([]string{"_airplay._tcp.local.", "_googlecast._tcp.local."})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil {
		t.Fatalf("parse start: %v", err)
	}
	if h.Response {
		t.Fatal("query should not have the response bit set")
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatalf("questions: %v", err)
	}
	if len(qs) != 2 {
		t.Fatalf("got %d questions, want 2", len(qs))
	}
	// QU (unicast-response) bit must be set: class 0x8001.
	if qs[0].Class != dnsmessage.Class(0x8001) {
		t.Errorf("question class = %#x, want 0x8001 (QU|IN)", qs[0].Class)
	}
	if qs[0].Type != dnsmessage.TypePTR {
		t.Errorf("question type = %v, want PTR", qs[0].Type)
	}
}

// buildMDNSAnswer constructs a synthetic mDNS response advertising an AirPlay
// service (PTR + TXT model=) for an Apple TV, to exercise parseMDNSResponse.
func buildMDNSAnswer(t *testing.T) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("build answer: %v", err)
		}
	}
	must(b.StartAnswers())
	svc := dnsmessage.MustNewName("_airplay._tcp.local.")
	inst := dnsmessage.MustNewName("Living Room._airplay._tcp.local.")
	must(b.PTRResource(
		dnsmessage.ResourceHeader{Name: svc, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120},
		dnsmessage.PTRResource{PTR: inst},
	))
	must(b.TXTResource(
		dnsmessage.ResourceHeader{Name: inst, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120},
		dnsmessage.TXTResource{TXT: []string{"srcvers=770.8.1", "model=AppleTV14,1", "deviceid=aa:bb:cc:dd:ee:ff"}},
	))
	out, err := b.Finish()
	must(err)
	return out
}

func TestParseMDNSResponse(t *testing.T) {
	data := buildMDNSAnswer(t)
	f := &mdnsFindings{}
	svcSet := map[string]bool{}
	parseMDNSResponse(data, f, svcSet)
	for s := range svcSet {
		f.services = append(f.services, s)
	}

	if !svcSet["_airplay"] {
		t.Errorf("expected _airplay service, got %v", f.services)
	}
	if f.model != "AppleTV14,1" {
		t.Errorf("model = %q, want AppleTV14,1", f.model)
	}
	if f.name != "Living Room" {
		t.Errorf("name = %q, want \"Living Room\"", f.name)
	}
}

func TestMDNSFindingsHasService(t *testing.T) {
	f := &mdnsFindings{services: []string{"_airplay", "_companion-link"}}
	if !f.hasService("_googlecast", "_airplay") {
		t.Error("expected _airplay to match")
	}
	if f.hasService("_googlecast", "_dial") {
		t.Error("did not expect a Cast match")
	}
	if (&mdnsFindings{}).hasService("_airplay") {
		t.Error("empty findings should match nothing")
	}
}

func TestInstanceName(t *testing.T) {
	cases := map[string]string{
		"Living Room._airplay._tcp.local": "Living Room",
		"Office Printer._ipp._tcp.local":  "Office Printer",
		"_airplay._tcp.local":             "", // service name, no instance
		"nas.local":                       "", // not a DNS-SD name
	}
	for in, want := range cases {
		if got := instanceName(in); got != want {
			t.Errorf("instanceName(%q) = %q, want %q", in, got, want)
		}
	}
}
