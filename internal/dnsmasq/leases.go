// Package dnsmasq parses OpenWrt's /tmp/dhcp.leases file so we can attach
// hostnames to MACs we see on the paid network.
package dnsmasq

import (
	"bufio"
	"os"
	"strings"
)

// Lease is one DHCP lease entry.
type Lease struct {
	MAC      string // uppercase AA:BB:CC:DD:EE:FF
	IP       string
	Hostname string
}

// Default path on OpenWrt.
const DefaultLeasesPath = "/tmp/dhcp.leases"

// LoadLeases reads dnsmasq's leases file.
// Format: "<expire-epoch> <mac> <ip> <hostname> <client-id>"
// Returns empty slice if the file doesn't exist.
func LoadLeases(path string) ([]Lease, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Lease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		mac := strings.ToUpper(fields[1])
		ip := fields[2]
		host := fields[3]
		if host == "*" {
			host = ""
		}
		out = append(out, Lease{MAC: mac, IP: ip, Hostname: host})
	}
	return out, sc.Err()
}

// HostnameByMAC reads the leases file and returns a MAC→hostname map.
func HostnameByMAC(path string) map[string]string {
	leases, _ := LoadLeases(path)
	m := make(map[string]string, len(leases))
	for _, l := range leases {
		if l.Hostname != "" {
			m[l.MAC] = l.Hostname
		}
	}
	return m
}
