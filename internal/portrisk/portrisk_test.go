package portrisk

import "testing"

func TestClassify(t *testing.T) {
	cases := map[int]string{
		23: "high", 3306: "medium", 80: "low", 5901: "high", 513: "medium",
		2049: "high", 5984: "high", 2379: "high", 10250: "high", // NFS, CouchDB, etcd, kubelet
		1883: "medium", 1900: "medium", 9100: "medium", 110: "medium", 5060: "medium",
		6443: "medium", 8500: "medium", 9092: "medium", 15672: "medium", // k8s API, Consul, Kafka, RabbitMQ
	}
	for port, sev := range cases {
		r, ok := Classify(port)
		if !ok || r.Severity != sev {
			t.Errorf("Classify(%d) = %+v,%v want severity %q", port, r, ok, sev)
		}
	}
	for _, normal := range []int{22, 443, 53} {
		if _, ok := Classify(normal); ok {
			t.Errorf("port %d should not be flagged", normal)
		}
	}
}
