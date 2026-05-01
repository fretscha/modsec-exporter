package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fretscha/modsec-exporter/internal/aggregator"
	"github.com/fretscha/modsec-exporter/internal/geoip"
	"github.com/fretscha/modsec-exporter/internal/metrics"
	"github.com/fretscha/modsec-exporter/internal/server"
	"github.com/fretscha/modsec-exporter/internal/tail"
)

// version is injected at build time via -ldflags.
var version = "dev"

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		accessPath = flag.String("access-log", envOr("MODSEC_EXPORTER_ACCESS_LOG", ""), "path to Apache access.log (required)")
		errorPath  = flag.String("error-log", envOr("MODSEC_EXPORTER_ERROR_LOG", ""), "path to ModSecurity error.log (required)")
		listen     = flag.String("listen", envOr("MODSEC_EXPORTER_LISTEN", ":9555"), "HTTP listen address")
		mmdbPath   = flag.String("mmdb", envOr("MODSEC_EXPORTER_MMDB", ""), "path to MMDB for GeoIP fallback (empty = disabled)")
		topN       = flag.Int("top-n", 50, "size of top-N attacker tracker (0 = disabled)")
		bufferSize = flag.Int("buffer-size", 50000, "max pending unique_ids in join buffer")
		bufferTTL  = flag.Duration("buffer-ttl", 60*time.Second, "max age of pending join entry")
		sweepEvery = flag.Duration("sweep-interval", 10*time.Second, "TTL sweep cadence")
		replay     = flag.Bool("replay", false, "one-shot mode: read both files start->EOF then exit")
	)
	flag.Parse()

	if *accessPath == "" || *errorPath == "" {
		log.Fatal("--access-log and --error-log are required")
	}

	m := metrics.New()
	m.BuildInfo.WithLabelValues(version, runtime.Version()).Set(1)

	var lookup geoip.Lookup = geoip.Disabled{}
	if *mmdbPath != "" {
		mm, err := geoip.NewMMDB(*mmdbPath, 10000)
		if err != nil {
			log.Printf("[WARN] mmdb open failed: %v — running with geoip disabled", err)
			m.GeoIPLookups.WithLabelValues("disabled").Inc()
		} else {
			defer mm.Close()
			lookup = mm
		}
	}

	agg := aggregator.New(m, lookup, aggregator.Config{
		BufferSize: *bufferSize,
		BufferTTL:  *bufferTTL,
		TopN:       *topN,
		Now:        time.Now,
	})

	var seen uint64
	ready := func() bool { return atomic.LoadUint64(&seen) > 0 }

	srv := server.New(*listen, m.Registry, ready)
	go func() {
		log.Printf("[INFO] listening on %s", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var (
		accessTailer tail.Tailer
		errorTailer  tail.Tailer
		err          error
	)
	if *replay {
		if accessTailer, err = tail.NewReplay(*accessPath); err != nil {
			log.Fatalf("access replay: %v", err)
		}
		if errorTailer, err = tail.NewReplay(*errorPath); err != nil {
			log.Fatalf("error replay: %v", err)
		}
	} else {
		if accessTailer, err = tail.NewFile(*accessPath); err != nil {
			log.Fatalf("access tail: %v", err)
		}
		if errorTailer, err = tail.NewFile(*errorPath); err != nil {
			log.Fatalf("error tail: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tail.Run(ctx, accessTailer,
			func(line string) { agg.OnRawAccess(line); atomic.AddUint64(&seen, 1) },
			func(err error) { m.TailErrors.WithLabelValues("access").Inc(); log.Printf("[WARN] access tail: %v", err) },
		)
	}()
	go func() {
		defer wg.Done()
		tail.Run(ctx, errorTailer,
			func(line string) { agg.OnRawError(line); atomic.AddUint64(&seen, 1) },
			func(err error) { m.TailErrors.WithLabelValues("error").Inc(); log.Printf("[WARN] error tail: %v", err) },
		)
	}()

	// TTL sweep ticker.
	go func() {
		t := time.NewTicker(*sweepEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				agg.SweepOrphans()
			}
		}
	}()

	wg.Wait()

	// Final sweep so any pending orphans are counted.
	agg.SweepOrphans()

	// In replay mode, wg.Wait() returns once both files reach EOF — but we
	// keep the HTTP server alive so scrapers can read the final state.
	// Exit only on SIGINT/SIGTERM. Live mode is already ctx-driven, so this
	// is a no-op there.
	if *replay {
		log.Printf("[INFO] replay complete; metrics endpoint stays up until SIGINT/SIGTERM")
	}
	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Printf("[INFO] shutdown complete")
}
