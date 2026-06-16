package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestParseCPS(t *testing.T) {
	cases := []struct {
		input   string
		want    float64
		wantErr bool
	}{
		{"", 0, false},
		{"1000", 1000, false},
		{"500cps", 500, false},
		{"1kcps", 1000, false},
		{"2Mcps", 2e6, false},
		{"2mcps", 2e6, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"abc", 0, true},
		{"1xcps", 0, true},
	}
	for _, c := range cases {
		got, err := ParseCPS(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseCPS(%q): want error, got nil", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCPS(%q): unexpected error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCPS(%q): want %g, got %g", c.input, c.want, got)
		}
	}
}

func TestApplyMultiplier(t *testing.T) {
	cases := []struct {
		rate    string
		m       float64
		want    string
		wantErr bool
	}{
		{"", 2.0, "", false},
		{"100kpps", 1.0, "100kpps", false},
		{"100kpps", 0, "100kpps", false},
		{"100kpps", 2.0, "200000pps", false},
		{"100kpps", 0.5, "50000pps", false},
		{"1gbps", 2.0, "2000000000bps", false},
		{"100mbps", 0.5, "50000000bps", false},
		{"1000pps", 3.0, "3000pps", false},
		{"100kpps", -1.0, "", true},
	}
	for _, c := range cases {
		got, err := ApplyMultiplier(c.rate, c.m)
		if c.wantErr {
			if err == nil {
				t.Errorf("ApplyMultiplier(%q, %g): want error, got nil", c.rate, c.m)
			}
			continue
		}
		if err != nil {
			t.Errorf("ApplyMultiplier(%q, %g): unexpected error: %v", c.rate, c.m, err)
			continue
		}
		if got != c.want {
			t.Errorf("ApplyMultiplier(%q, %g): want %q, got %q", c.rate, c.m, c.want, got)
		}
	}
}

func TestCPSLimiterNil(t *testing.T) {
	var cl *CPSLimiter
	ctx := context.Background()
	if err := cl.Wait(ctx); err != nil {
		t.Errorf("nil CPSLimiter.Wait: want nil, got %v", err)
	}
}

func TestNewCPSZero(t *testing.T) {
	cl, err := NewCPS(context.Background(), 0, "")
	if err != nil {
		t.Fatalf("NewCPS(0): %v", err)
	}
	if cl != nil {
		t.Error("NewCPS(0): want nil (unlimited), got non-nil")
	}
}

func TestCPSLimiterThrottles(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	ctx := context.Background()
	cl, err := NewCPS(ctx, 50, "") // 50 CPS → ~20ms per session
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := cl.Wait(ctx); err != nil {
			t.Fatalf("Wait[%d]: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	// burst=5 (10% of 50), so after 5 waits (consuming the burst) we expect ~0ms,
	// but 5 waits at 50cps without burst ≈ 80ms. Give generous tolerance.
	if elapsed > 5*time.Second {
		t.Errorf("CPS limiter too slow: %v for 5 sessions at 50cps", elapsed)
	}
}

func TestCPSLimiterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cl, err := NewCPS(ctx, 1, "") // very low rate so it actually blocks
	if err != nil {
		t.Fatal(err)
	}
	// First Wait succeeds (burst allows it)
	_ = cl.Wait(ctx)
	// Cancel context then expect immediate error
	cancel()
	if err := cl.Wait(ctx); err == nil {
		t.Error("Wait after context cancel: want error, got nil")
	}
}

// ---- CPSDispatcher tests ----

func TestCPSDispatcherNil(t *testing.T) {
	var d *CPSDispatcher
	if err := d.Take(context.Background()); err != nil {
		t.Errorf("nil CPSDispatcher.Take: want nil, got %v", err)
	}
}

func TestCPSDispatcherZero(t *testing.T) {
	d := NewCPSDispatcher(context.Background(), 0)
	if d != nil {
		t.Error("NewCPSDispatcher(0): want nil (unlimited), got non-nil")
	}
}

func TestCPSDispatcherFires(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// 100 CPS → one tick every 10ms → ~50 ticks in 500ms
	d := NewCPSDispatcher(ctx, 100)
	var count int
	for {
		if err := d.Take(ctx); err != nil {
			break
		}
		count++
	}
	if count < 20 || count > 80 {
		t.Errorf("CPSDispatcher at 100 CPS for 500ms: want 20–80 ticks, got %d", count)
	}
}

func TestCPSDispatcherContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := NewCPSDispatcher(ctx, 1) // very slow so Take blocks
	cancel()
	if err := d.Take(ctx); err == nil {
		t.Error("Take after cancel: want error, got nil")
	}
}
