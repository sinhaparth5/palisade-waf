package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// BenchmarkDashboardQueries times the dashboard queries over a request log
// spread across 30 days (#288). 200k rows by default; BENCH_ROWS=1000000 for
// the figures in BENCHMARKS.md. SQLite only.
func BenchmarkDashboardQueries(b *testing.B) {
	rows := 200_000
	if n, err := strconv.Atoi(os.Getenv("BENCH_ROWS")); err == nil {
		rows = n
	}
	db, err := Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	step := 30 * 24 * time.Hour / time.Duration(rows)
	batch := make([]RequestLog, 0, logBatchMax)
	for i := range rows {
		r := RequestLog{
			Timestamp: now.Add(-time.Duration(i) * step),
			RealIP:    fmt.Sprintf("203.0.%d.%d", i%200, i%250),
			Country:   []string{"US", "DE", "IN", "BR", "CN"}[i%5],
			Method:    "GET", Path: "/", Status: 200, Duration: int64(i % 40),
			VisitorID: strconv.Itoa(i % 5000),
		}
		if i%10 == 0 {
			r.Blocked, r.Status, r.RuleID, r.Action = true, 403, 942100+i%7, "waf_blocked"
		}
		if batch = append(batch, r); len(batch) == cap(batch) {
			db.insertRequestBatch(batch)
			batch = batch[:0]
		}
	}
	db.insertRequestBatch(batch)

	for name, fn := range map[string]func() error{
		"Stats":          func() error { _, err := db.GetStats(); return err },
		"AtAGlance":      func() error { _, err := db.GetAtAGlanceStats(); return err },
		"HourlyTraffic":  func() error { _, err := db.GetHourlyTraffic(24); return err },
		"TopFiringRules": func() error { _, err := db.GetTopFiringRules(10); return err },
		"RuleHitCounts":  func() error { _, err := db.GetRuleHitCounts(942000, 942999); return err },
		"TopCountries":   func() error { _, err := db.GetTopCountries(5, 24); return err },
	} {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if err := fn(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
