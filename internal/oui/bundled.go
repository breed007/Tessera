package oui

// table maps lowercase OUI prefixes ("xx:xx:xx") to vendor names. This is a
// curated subset of the IEEE registry covering common homelab/IoT vendors —
// enough to give useful vendor attribution out of the box. Replace with the full
// IEEE OUI registry for complete coverage; the keys are the first three octets.
var table = map[string]string{
	// Raspberry Pi
	"b8:27:eb": "Raspberry Pi Foundation",
	"dc:a6:32": "Raspberry Pi Trading",
	"e4:5f:01": "Raspberry Pi Trading",
	"d8:3a:dd": "Raspberry Pi Trading",
	// Ubiquiti
	"f0:9f:c2": "Ubiquiti Networks",
	"24:a4:3c": "Ubiquiti Networks",
	"fc:ec:da": "Ubiquiti Networks",
	"68:d7:9a": "Ubiquiti Networks",
	"74:83:c2": "Ubiquiti Networks",
	// Apple
	"f0:18:98": "Apple",
	"3c:15:c2": "Apple",
	"ac:bc:32": "Apple",
	"a4:83:e7": "Apple",
	"f4:f1:5a": "Apple",
	"d0:81:7a": "Apple",
	// Espressif (ESP8266/ESP32 — lots of DIY IoT)
	"24:0a:c4": "Espressif",
	"30:ae:a4": "Espressif",
	"7c:9e:bd": "Espressif",
	"a0:20:a6": "Espressif",
	"ec:fa:bc": "Espressif",
	// Intel
	"00:1b:21": "Intel",
	"3c:fd:fe": "Intel",
	"a4:bb:6d": "Intel",
	// Samsung
	"5c:0a:5b": "Samsung Electronics",
	"e8:50:8b": "Samsung Electronics",
	"00:12:fb": "Samsung Electronics",
	// Google / Nest
	"f4:f5:d8": "Google",
	"da:a1:19": "Google",
	"1c:f2:9a": "Google",
	// Amazon
	"fc:65:de": "Amazon Technologies",
	"68:37:e9": "Amazon Technologies",
	"44:65:0d": "Amazon Technologies",
	// TP-Link
	"50:c7:bf": "TP-Link",
	"a4:2b:b0": "TP-Link",
	// Sonos
	"5c:aa:fd": "Sonos",
	"94:9f:3e": "Sonos",
	// Philips Hue
	"00:17:88": "Philips Lighting (Hue)",
	// Synology
	"00:11:32": "Synology",
	// Texas Instruments (Zigbee/BLE)
	"00:12:4b": "Texas Instruments",
}
