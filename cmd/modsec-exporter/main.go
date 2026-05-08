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
	"github.com/fretscha/modsec-exporter/internal/config"
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
		configPath = flag.String("config", "", "path to TOML config file (mutually exclusive with --access-log/--error-log)")
		accessPath = flag.String("access-log", envOr("MODSEC_EXPORTER_ACCESS_LOG", ""), "path to Apache access.log (single-site; required if --config not given)")
		errorPath  = flag.String("error-log", envOr("MODSEC_EXPORTER_ERROR_LOG", ""), "path to ModSecurity error.log (single-site; required if --config not given)")
		listen     = flag.String("listen", envOr("MODSEC_EXPORTER_LISTEN", ":9555"), "HTTP listen address")
		mmdbPath   = flag.String("mmdb", envOr("MODSEC_EXPORTER_MMDB", ""), "path to MMDB for GeoIP fallback (empty = disabled)")
		topN       = flag.Int("top-n", 50, "size of top-N attacker tracker per site (0 = disabled)")
		bufferSize = flag.Int("buffer-size", 50000, "max pending unique_ids in join buffer per site")
		bufferTTL  = flag.Duration("buffer-ttl", 60*time.Second, "max age of pending join entry")
		sweepEvery = flag.Duration("sweep-interval", 10*time.Second, "TTL sweep cadence")
		replay     = flag.Bool("replay", false, "one-shot mode: read all files start->EOF then exit")
	)
	flag.Parse()

	// Build the site list from a config file or from the legacy single-site flags.
	var sites []config.SiteConfig
	switch {
	case *configPath != "" && (*accessPath != "" || *errorPath != ""):
		log.Fatal("--config and --access-log/--error-log are mutually exclusive")
	case *configPath != "":
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		sites = cfg.Sites
	default:
		if *accessPath == "" || *errorPath == "" {
			log.Fatal("--access-log and --error-log are required when --config is not given")
		}
		sites = []config.SiteConfig{{Name: "default", AccessLog: *accessPath, ErrorLog: *errorPath}}
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
			defer func() { _ = mm.Close() }()
			lookup = mm
		}
	}

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

	aggCfg := aggregator.Config{
		BufferSize: *bufferSize,
		BufferTTL:  *bufferTTL,
		TopN:       *topN,
		Now:        time.Now,
	}

	aggs := make([]*aggregator.Aggregator, len(sites))
	for i, sc := range sites {
		aggs[i] = aggregator.New(m, lookup, aggCfg, sc.Name)
	}

	var wg sync.WaitGroup
	for i, sc := range sites {
		agg := aggs[i]
		siteName := sc.Name

		var accessTailer, errorTailer tail.Tailer
		var err error
		if *replay {
			if accessTailer, err = tail.NewReplay(sc.AccessLog); err != nil {
				log.Fatalf("site %s access replay: %v", siteName, err)
			}
			if errorTailer, err = tail.NewReplay(sc.ErrorLog); err != nil {
				log.Fatalf("site %s error replay: %v", siteName, err)
			}
		} else {
			if accessTailer, err = tail.NewFile(sc.AccessLog); err != nil {
				log.Fatalf("site %s access tail: %v", siteName, err)
			}
			if errorTailer, err = tail.NewFile(sc.ErrorLog); err != nil {
				log.Fatalf("site %s error tail: %v", siteName, err)
			}
		}

		wg.Add(2)
		go func() {
			defer wg.Done()
			tail.Run(ctx, accessTailer,
				func(line string) { agg.OnRawAccess(line); atomic.AddUint64(&seen, 1) },
				func(e error) {
					m.TailErrors.WithLabelValues(siteName, "access").Inc()
					log.Printf("[WARN] site %s access tail: %v", siteName, e)
				},
			)
		}()
		go func() {
			defer wg.Done()
			tail.Run(ctx, errorTailer,
				func(line string) { agg.OnRawError(line); atomic.AddUint64(&seen, 1) },
				func(e error) {
					m.TailErrors.WithLabelValues(siteName, "error").Inc()
					log.Printf("[WARN] site %s error tail: %v", siteName, e)
				},
			)
		}()
	}

	// TTL sweep ticker covers all sites.
	go func() {
		t := time.NewTicker(*sweepEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, agg := range aggs {
					agg.SweepOrphans()
				}
			}
		}
	}()

	wg.Wait()

	// Final sweep so any pending orphans are counted.
	for _, agg := range aggs {
		agg.SweepOrphans()
	}

	if *replay {
		log.Printf("[INFO] replay complete; metrics endpoint stays up until SIGINT/SIGTERM")
	}
	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Printf("[INFO] shutdown complete")
}
