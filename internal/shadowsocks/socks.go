package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 address types, as they appear at the head of a Shadowsocks TCP
// stream (after decryption). The client sends the CONNECT target here.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// maxAddrLen bounds a parsed address: 1 (atyp) + 1 (domain len) + 255
// (domain) + 2 (port).
const maxAddrLen = 1 + 1 + 255 + 2

// targetAddr is a decoded CONNECT target plus its dial string.
type targetAddr struct {
	host string
	port int
}

func (t targetAddr) String() string {
	return net.JoinHostPort(t.host, strconv.Itoa(t.port))
}

// readTargetAddr reads and decodes the SOCKS5-style address header from a
// decrypted stream. It reads exactly the bytes the header needs — no more —
// so the remaining stream is the raw payload to relay.
func readTargetAddr(r io.Reader) (targetAddr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return targetAddr{}, err
	}
	switch atyp[0] {
	case atypIPv4:
		var b [net.IPv4len + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return targetAddr{}, err
		}
		host := net.IP(b[:net.IPv4len]).String()
		port := int(binary.BigEndian.Uint16(b[net.IPv4len:]))
		return targetAddr{host: host, port: port}, nil
	case atypIPv6:
		var b [net.IPv6len + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return targetAddr{}, err
		}
		host := net.IP(b[:net.IPv6len]).String()
		port := int(binary.BigEndian.Uint16(b[net.IPv6len:]))
		return targetAddr{host: host, port: port}, nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return targetAddr{}, err
		}
		n := int(l[0])
		if n == 0 {
			return targetAddr{}, errBadAddress
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return targetAddr{}, err
		}
		host := string(b[:n])
		port := int(binary.BigEndian.Uint16(b[n:]))
		return targetAddr{host: host, port: port}, nil
	default:
		return targetAddr{}, fmt.Errorf("%w: atyp=0x%02x", errBadAddress, atyp[0])
	}
}

// encodeTargetAddr serializes host:port back into the SOCKS5 wire form. Used
// by the in-test client and by anyone building a request header.
func encodeTargetAddr(host string, port int) ([]byte, error) {
	if port < 0 || port > 0xFFFF {
		return nil, fmt.Errorf("%w: port %d out of range", errBadAddress, port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := make([]byte, 0, 1+net.IPv4len+2)
			out = append(out, atypIPv4)
			out = append(out, v4...)
			out = binary.BigEndian.AppendUint16(out, uint16(port))
			return out, nil
		}
		out := make([]byte, 0, 1+net.IPv6len+2)
		out = append(out, atypIPv6)
		out = append(out, ip.To16()...)
		out = binary.BigEndian.AppendUint16(out, uint16(port))
		return out, nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("%w: domain length %d", errBadAddress, len(host))
	}
	out := make([]byte, 0, 1+1+len(host)+2)
	out = append(out, atypDomain, byte(len(host)))
	out = append(out, host...)
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	return out, nil
}
