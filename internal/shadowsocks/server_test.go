package shadowsocks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startServer boots a Server on 127.0.0.1:0 and returns its address plus a
// cancel func. The test's t.Cleanup stops it.
func startServer(t *testing.T, opts Options) (string, *Metrics) {
	t.Helper()
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Log("server did not stop within 3s")
		}
	})
	return ln.Addr().String(), opts.Metrics
}

// echoTCPServer accepts one line and echoes it back uppercased.
func echoTCPServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write([]byte(strings.ToUpper(string(buf[:n]))))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	ta := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", ta.Port
}

func TestServerRelayAllCiphers(t *testing.T) {
	targetHost, targetPort := echoTCPServer(t)
	for _, method := range SupportedMethods() {
		t.Run(method, func(t *testing.T) {
			addr, m := startServer(t, Options{
				Method:   method,
				Password: "hunter2-hunter2",
			})
			c, err := dialSS(addr, method, "hunter2-hunter2", targetHost, targetPort)
			if err != nil {
				t.Fatalf("dialSS: %v", err)
			}
			defer c.Close()

			msg := "hello, proxy!"
			if _, err := c.Write([]byte(msg)); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("read: %v", err)
			}
			if got := string(buf); got != strings.ToUpper(msg) {
				t.Fatalf("echo = %q, want %q", got, strings.ToUpper(msg))
			}
			// Give the metrics goroutine a beat to record the connection.
			waitFor(t, func() bool { return m.Snapshot().ConnectionsTotal == 1 })
			snap := m.Snapshot()
			if snap.BytesIn == 0 || snap.BytesOut == 0 {
				t.Errorf("byte counters not updated: %+v", snap)
			}
		})
	}
}

// TestServerHTTPThroughProxy proves a real HTTP request survives the proxy:
// httptest server as the origin, SS in the middle, minimal client speaking
// HTTP over the tunnel.
func TestServerHTTPThroughProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "PONG:%s", r.URL.Path)
	}))
	defer origin.Close()

	u := origin.URL // http://127.0.0.1:PORT
	hostport := strings.TrimPrefix(u, "http://")
	host, portStr, _ := net.SplitHostPort(hostport)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	addr, _ := startServer(t, Options{Method: "chacha20-ietf-poly1305", Password: "pw-pw-pw"})
	c, err := dialSS(addr, "chacha20-ietf-poly1305", "pw-pw-pw", host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req := "GET /hello HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "PONG:/hello") {
		t.Fatalf("body = %q, want PONG:/hello", body)
	}
}

func TestServerRejectsWrongPassword(t *testing.T) {
	targetHost, targetPort := echoTCPServer(t)
	addr, m := startServer(t, Options{Method: "aes-256-gcm", Password: "correct-password"})

	c, err := dialSS(addr, "aes-256-gcm", "WRONG-password", targetHost, targetPort)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// The server can't decrypt the header, so it drops the connection.
	_ = c.raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected connection to fail with wrong password")
	}
	waitFor(t, func() bool { return m.Snapshot().HandshakeErrors >= 1 })
}

func TestServerReplayRejected(t *testing.T) {
	_, targetPort := echoTCPServer(t)
	addr, m := startServer(t, Options{
		Method:       "aes-256-gcm",
		Password:     "replay-pw-1234",
		ReplayWindow: time.Minute,
	})

	handshake, err := dialSSRawHandshake(addr, "aes-256-gcm", "replay-pw-1234", "127.0.0.1", targetPort)
	if err != nil {
		t.Fatal(err)
	}

	// First replay of the captured handshake: accepted (salt is fresh).
	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn1.Write(handshake)
	conn1.Close()
	waitFor(t, func() bool { return m.Snapshot().ConnectionsTotal >= 1 })

	// Second send of the EXACT same bytes (same salt) must be rejected.
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn2.Write(handshake)
	conn2.Close()

	waitFor(t, func() bool { return m.Snapshot().ReplayRejected >= 1 })
	if m.Snapshot().ReplayRejected < 1 {
		t.Fatalf("expected a replay rejection, metrics=%+v", m.Snapshot())
	}
}

func TestServerSourceACL(t *testing.T) {
	targetHost, targetPort := echoTCPServer(t)
	// Allow only 10.0.0.0/8 — the test dials from 127.0.0.1, so it's blocked.
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	addr, m := startServer(t, Options{
		Method:       "aes-128-gcm",
		Password:     "acl-password-xyz",
		AllowedCIDRs: []*net.IPNet{cidr},
	})

	// The server drops the connection before/right after the handshake, so
	// dialSS may fail on write OR the subsequent read fails — either way the
	// client gets no data. What we assert on is the BlockedByACL counter.
	if c, err := dialSS(addr, "aes-128-gcm", "acl-password-xyz", targetHost, targetPort); err == nil {
		defer c.Close()
		_ = c.raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8)
		if _, err := c.Read(buf); err == nil {
			t.Fatal("expected ACL to block loopback client")
		}
	}
	waitFor(t, func() bool { return m.Snapshot().BlockedByACL >= 1 })
}

func TestServerGracefulShutdown(t *testing.T) {
	srv, err := NewServer(Options{Method: "aes-256-gcm", Password: "shutdown-pw-01", Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, ln) }()

	// Cancel and expect a clean nil return promptly.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil on cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

func TestNewServerValidation(t *testing.T) {
	if _, err := NewServer(Options{Method: "rc4-md5", Password: "x"}); err == nil {
		t.Error("expected error for bad method")
	}
	if _, err := NewServer(Options{Method: "aes-256-gcm", Password: ""}); err == nil {
		t.Error("expected error for empty password")
	}
}

// waitFor polls cond up to 2s. Byte/connection counters are updated by the
// relay goroutines slightly after the client observes data.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within timeout")
	}
}
