package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"router-billing/internal/backup"
	"router-billing/internal/config"
	"router-billing/internal/db"
	"router-billing/internal/dnsmasq"
	"router-billing/internal/firewall"
	"router-billing/internal/scheduler"
	"router-billing/internal/server"
	"router-billing/internal/service"
	"router-billing/internal/sightings"
	"router-billing/internal/walledgarden"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/router-billing/config.yaml", "path to config.yaml")
	dryFirewall := flag.Bool("dry-firewall", false, "log nft commands without executing (dev only)")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check-config", false, "validate the config file and exit")
	genHash := flag.Bool("gen-password-hash", false, "read a password from stdin and print its bcrypt hash; ideal for admins[].password_hash")
	genTOTP := flag.String("gen-totp-secret", "", "generate a fresh TOTP secret for the given admin username; prints base32 + otpauth URL + ASCII QR")
	logJSON := flag.Bool("log-json", false, "emit each log line as a JSON object (for ingestion into ELK/Loki/etc.)")
	flag.Parse()

	if *logJSON {
		setupJSONLogger(version)
	} else {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	if *showVersion {
		fmt.Printf("router-billing %s\n", version)
		return
	}
	if *genHash {
		runGenHash()
		return
	}
	if *genTOTP != "" {
		runGenTOTP(*genTOTP)
		return
	}
	if *checkConfig {
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "config %s: %v\n", *cfgPath, err)
			os.Exit(2)
		}
		fmt.Printf("config %s: OK\n", *cfgPath)
		return
	}

	log.Printf("router-billing %s starting (config=%s)", version, *cfgPath)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// If the admin uploaded a backup via /admin/backup/restore, the file is
	// staged as <db>.pending-restore. Apply it BEFORE opening the DB pool.
	if err := server.MaybeApplyPendingRestore(cfg.DBPath); err != nil {
		log.Printf("warn: pending restore not applied: %v", err)
	}
	dbx, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer dbx.Close()

	fw, err := firewall.NewBackend(cfg.Firewall.Backend, cfg.Firewall.Table, cfg.Firewall.TableName,
		cfg.Firewall.SetName, cfg.PaidIface, *dryFirewall)
	if err != nil {
		log.Fatalf("firewall: %v", err)
	}
	if *dryFirewall {
		log.Printf("firewall: dry-run mode enabled (backend=%s)", strings.ToLower(strings.TrimSpace(cfg.Firewall.Backend)))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := fw.EnsureSet(ctx); err != nil {
		log.Printf("warn: firewall ensure set: %v (continuing)", err)
	}

	svc := service.New(dbx, fw)
	if err := svc.Resync(ctx); err != nil {
		log.Printf("warn: initial firewall resync: %v (continuing)", err)
	}

	// Background goroutines.
	go scheduler.Run(ctx, svc, cfg.Scheduler.ExpireCheckInterval)
	go svc.EnforceSchedules(ctx)
	tracker := &sightings.Tracker{
		DB:         dbx,
		Iface:      cfg.PaidIface,
		LeasesPath: dnsmasq.DefaultLeasesPath,
	}
	go tracker.Run(ctx)

	// Walled garden: resolve and inject configured domains so unpaid users can
	// reach payment infrastructure without being whitelisted first.
	// Currently nftables-only — the IP-set side needs daddr matching that
	// the iptables/ipset backend doesn't manage. Type-assert and skip
	// gracefully on the iptables backend.
	if len(cfg.WalledGarden.Domains) > 0 {
		if nftMgr, ok := fw.(*firewall.Manager); ok {
			wg := &walledgarden.Resolver{
				FW:              nftMgr,
				SetName:         "wg_paid",
				Domains:         cfg.WalledGarden.Domains,
				RefreshInterval: cfg.WalledGarden.RefreshInterval,
			}
			go wg.Run(ctx)
		} else {
			log.Printf("walled garden: configured but skipped — only the nftables backend supports it")
		}
	}

	if cfg.Backup.Enabled {
		rot := &backup.Rotator{
			DB:         dbx,
			DBPath:     cfg.DBPath,
			Dir:        cfg.Backup.Dir,
			RetainDays: cfg.Backup.RetainDays,
			Interval:   cfg.Backup.Interval,
			Enabled:    true,
		}
		go rot.Run(ctx)
	}

	// Hourly daily-stats snapshot for the dashboard chart.
	go func() {
		_ = dbx.SnapshotToday(ctx)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = dbx.SnapshotToday(ctx)
			}
		}
	}()

	app, err := server.NewApp(cfg, dbx, svc)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}
	app.Version = version
	if err := app.Run(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Printf("router-billing exited cleanly")
}

// runGenHash reads a single line from stdin (no echo if TTY) and prints a
// bcrypt hash suitable for paste into admins[].password_hash.
func runGenHash() {
	fmt.Print("password: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "no input")
		os.Exit(2)
	}
	p := strings.TrimRight(scanner.Text(), "\r\n")
	if len(p) < 6 {
		fmt.Fprintln(os.Stderr, "password must be at least 6 chars")
		os.Exit(2)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(h))
}
