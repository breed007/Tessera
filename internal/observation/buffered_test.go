package observation

import (
	"context"
	"testing"
	"time"
)

type fakeBatch struct {
	got     []Observation
	batches int
}

func (f *fakeBatch) Append(_ context.Context, o Observation) (int64, error) {
	f.got = append(f.got, o)
	return 0, nil
}
func (f *fakeBatch) AppendBatch(_ context.Context, b []Observation) error {
	f.batches++
	f.got = append(f.got, b...)
	return nil
}

func sampleObs() Observation {
	return Observation{
		ObservedAt: time.Unix(1700000000, 0), Source: SourcePassiveARP, CollectorID: "t",
		SubjectType: SubjectMAC, Subject: "aa:bb:cc:dd:ee:ff", Attribute: AttrLiveness, Value: "up", Confidence: 90,
	}
}

func TestBufferedFlushesOnShutdown(t *testing.T) {
	fb := &fakeBatch{}
	b := NewBufferedAppender(fb, 100, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()

	for i := 0; i < 10; i++ {
		_, _ = b.Append(ctx, sampleObs())
	}
	cancel() // shutdown → worker drains the queue and flushes
	<-done

	if len(fb.got) != 10 {
		t.Errorf("flushed %d observations, want 10", len(fb.got))
	}
	if fb.batches == 0 {
		t.Error("expected the batch fast path to be used")
	}
}

func TestBufferedDropsWhenFull(t *testing.T) {
	fb := &fakeBatch{}
	b := NewBufferedAppender(fb, 2, nil) // tiny queue, worker NOT running → fills up
	for i := 0; i < 5; i++ {
		_, _ = b.Append(context.Background(), sampleObs())
	}
	// 2 fit in the buffer; the other 3 are dropped (backpressure), not blocked.
	if b.Dropped() != 3 {
		t.Errorf("dropped = %d, want 3", b.Dropped())
	}
}
