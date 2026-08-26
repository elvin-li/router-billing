package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"router-billing/internal/config"
	"router-billing/internal/firewall"
	"router-billing/internal/shadowsocks"
)

// startShadowsocks boots the optional built-in Shadowsocks proxy when
// enabled in config, wiring it to the process context for graceful shutdown.
// Returns the live metrics set (nil when disabled) so the HTTP server can
// expose it on /metrics and the admin page.
func startShadowsocks(ctx context.Context, cfg *config.Config, fw firewall.API) *shadowsocks.Metrics {
	if !cfg.Shadowsocks.Enabled {
		return nil
	}
	m := &shadowsocks.Metrics{}
	cidrs, err := cfg.Shadowsocks.ParsedCIDRs()
	if err != nil {
		log.Fatalf("shadowsocks allowed_cidrs: %v", err)
	}
	ssrv, err := shadowsocks.NewServer(shadowsocks.Options{
		Method:       cfg.Shadowsocks.Method,
		Password:     cfg.Shadowsocks.Password,
		AllowedCIDRs: cidrs,
		MaxConns:     cfg.Shadowsocks.MaxConns,
		Timeout:      cfg.Shadowsocks.Timeout,
		ReplayWindow: cfg.Shadowsocks.ReplayWindow,
		Metrics:      m,
		Logf:         log.Printf,
	})
	if err != nil {
		log.Fatalf("shadowsocks init: %v", err)
	}
	// Best-effort firewall opening (nftables backend only).
	if cfg.Shadowsocks.OpenFirewall {
		if nftMgr, ok := fw.(*firewall.Manager); ok {
			if err := nftMgr.EnsureInputAccept(ctx, "ss_in", cfg.Shadowsocks.FirewallIface,
				cfg.Shadowsocks.ListenPort()); err != nil {
				log.Printf("shadowsocks: open firewall port: %v (continuing)", err)
			}
		} else {
			log.Printf("shadowsocks: open_firewall set but backend is not nftables — add the rule manually")
		}
	}
	listen := cfg.Shadowsocks.Listen
	go func() {
		if err := ssrv.ListenAndServe(ctx, listen); err != nil {
			log.Printf("shadowsocks: %v", err)
		}
	}()
	log.Printf("shadowsocks: enabled on %s (method=%s)", listen, cfg.Shadowsocks.Method)
	return m
}

// runGenSSPassword prints a fresh, strong Shadowsocks password. The value is
// 32 random bytes base64-encoded (~43 chars) — far beyond brute-force reach.
// The operator pastes it into config.yaml's shadowsocks.password, then can
// run `--ss-uri` to get the share link/QR.
func runGenSSPassword() {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		os.Exit(2)
	}
	pw := base64.RawURLEncoding.EncodeToString(raw)

	fmt.Println()
	fmt.Println("================= router-billing Shadowsocks =================")
	fmt.Println()
	fmt.Println("Generated password (256-bit):")
	fmt.Println()
	fmt.Println("   " + pw)
	fmt.Println()
	fmt.Println("Add it to config.yaml:")
	fmt.Println()
	fmt.Println("   shadowsocks:")
	fmt.Println("     enabled: true")
	fmt.Println("     listen: \"192.168.5.1:8388\"   # bind LAN-only!")
	fmt.Println("     method: \"chacha20-ietf-poly1305\"")
	fmt.Printf("     password: \"%s\"\n", pw)
	fmt.Println()
	fmt.Println("Then run  --ss-uri  to print the ss:// share link + QR.")
	fmt.Println("SECURITY: bind to the LAN interface only; do NOT expose on")
	fmt.Println("the paid SSID or WAN without a firewall rule + strong password.")
	fmt.Println("==============================================================")
}

// runSSURI loads the config and prints the ss:// share link plus an ASCII QR
// for the configured Shadowsocks server. Useful for wiring a client without
// opening the admin UI. The link embeds the password — treat the terminal
// output as sensitive.
func runSSURI(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", cfgPath, err)
		os.Exit(2)
	}
	ss := cfg.Shadowsocks
	if !ss.Enabled {
		fmt.Fprintln(os.Stderr, "shadowsocks is not enabled in config; nothing to share")
		os.Exit(2)
	}
	if ss.Password == "" {
		fmt.Fprintln(os.Stderr, "shadowsocks.password is empty; run --gen-ss-password first")
		os.Exit(2)
	}
	host := ss.AdvertiseHostOr(cfg.PortalHost)
	if host == "" {
		host = "192.168.5.1"
	}
	uri, err := shadowsocks.ShareURI(ss.Method, ss.Password, host, ss.ListenPort(), ss.TagOr())
	if err != nil {
		fmt.Fprintf(os.Stderr, "build ss uri: %v\n", err)
		os.Exit(2)
	}

	fmt.Println()
	fmt.Println("================= router-billing Shadowsocks =================")
	fmt.Println()
	fmt.Println("Method: ", ss.Method)
	fmt.Println("Server: ", host+":"+itoaPort(ss.ListenPort()))
	fmt.Println()
	fmt.Println("Share link (contains the password — keep it private):")
	fmt.Println()
	fmt.Println("   " + uri)
	fmt.Println()
	fmt.Println("QR (scan into Shadowsocks / Outline / Clash / official apps):")
	if err := printASCIIQR(uri); err != nil {
		fmt.Fprintf(os.Stderr, "qr: %v\n", err)
	}
	fmt.Println()
	fmt.Println("==============================================================")
}

func itoaPort(p int) string {
	return fmt.Sprintf("%d", p)
}
