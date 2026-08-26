package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ShareURI builds an ss:// share link in the SIP002 format that modern
// clients (Shadowsocks-rust, Outline, Clash, iOS/Android) recognize:
//
//	ss://base64url(method:password)@host:port#tag
//
// The userinfo is base64url-encoded WITHOUT padding, per SIP002. host is the
// address a client should dial — typically the router's LAN IP or, for
// remote access, a public host/DDNS name. tag is an optional human label
// shown in the client (URL-fragment-escaped).
//
// SECURITY: the returned string embeds the password. Treat it like a
// credential — it is only ever shown to an authenticated admin on the
// one-time reveal, never logged.
func ShareURI(method, password, host string, port int, tag string) (string, error) {
	if !ValidMethod(method) {
		return "", fmt.Errorf("shadowsocks: %w", errUnsupported(method))
	}
	if password == "" {
		return "", fmt.Errorf("shadowsocks: empty password")
	}
	if port <= 0 || port > 0xFFFF {
		return "", fmt.Errorf("shadowsocks: port %d out of range", port)
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(normalizeMethod(method) + ":" + password))
	hostport := net.JoinHostPort(host, strconv.Itoa(port))
	uri := "ss://" + userinfo + "@" + hostport
	if tag != "" {
		uri += "#" + urlFragmentEscape(tag)
	}
	return uri, nil
}

func errUnsupported(method string) error {
	return fmt.Errorf("unsupported method %q", method)
}

// urlFragmentEscape escapes a tag for safe inclusion after '#'. url.QueryEscape
// is overly aggressive (turns spaces into '+') so we use PathEscape which is
// closer to how clients render the fragment label.
func urlFragmentEscape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "+", "%20")
}
