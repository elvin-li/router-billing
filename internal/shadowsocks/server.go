package shadowsocks

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning values used when the corresponding Options field is zero.
const (
	defaultTimeout      = 5 * time.Minute
	defaultHandshakeTO  = 15 * time.Second
	defaultReplayWindow = 60 * time.Second
	defaultMaxConns     = 512
	shutdownDrain       = 10 * time.Second
)

// Options configures a Server. Only Method + Password are required; the rest
// have safe defaults.
type Options struct {
	Method   string
	Password string
	// AllowedCIDRs, when non-empty, restricts which client source IPs may
	// connect. Anything outside the list is dropped before the handshake.
	// This is the in-process complement to binding LAN-only + firewalling
	// the port — defense in depth so a misconfigured bind can't hand the
	// proxy to the paid SSID.
	AllowedCIDRs []*net.IPNet
	// MaxConns caps concurrent relays (0 → defaultMaxConns).
	MaxConns int
	// Timeout is the per-direction idle timeout for an established relay
	// (0 → defaultTimeout).
	Timeout time.Duration
	// ReplayWindow is how long a salt is remembered for replay rejection
	// (0 → defaultReplayWindow; negative → disabled).
	ReplayWindow time.Duration
	// Logf, if set, receives operational log lines. Never receives secrets.
	Logf func(format string, args ...any)
	// Metrics, if set, is updated as connections come and go.
	Metrics *Metrics
	// Dialer overrides how target connections are made (tests inject this).
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is a running (or ready-to-run) Shadowsocks AEAD TCP proxy.
type Server struct {
	opts      Options
	spec      *CipherSpec
	masterKey []byte
	replay    *replayFilter
	sem       chan struct{}
	metrics   *Metrics
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)

	wg sync.WaitGroup
}

// NewServer validates the options and builds a Server. It does not bind any
// socket — call ListenAndServe or Serve.
func NewServer(opts Options) (*Server, error) {
	spec, err := LookupCipher(opts.Method)
	if err != nil {
		return nil, err
	}
	if opts.Password == "" {
		return nil, errors.New("shadowsocks: password is required")
	}
	maxConns := opts.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	window := opts.ReplayWindow
	if window == 0 {
		window = defaultReplayWindow
	}
	dial := opts.Dialer
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	s := &Server{
		opts:      opts,
		spec:      spec,
		masterKey: DeriveKey(opts.Password, spec.KeySize),
		replay:    newReplayFilter(window, 0),
		sem:       make(chan struct{}, maxConns),
		metrics:   opts.Metrics,
		dial:      dial,
	}
	return s, nil
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

// ListenAndServe binds opts.-derived listen address and serves until ctx is
// canceled. It is a convenience wrapper over Serve.
func (s *Server) ListenAndServe(ctx context.Context, listen string) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		return fmt.Errorf("shadowsocks listen %s: %w", listen, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is canceled, then closes ln and
// drains in-flight relays (up to shutdownDrain). Always returns nil on a
// clean context-cancel shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.logf("shadowsocks: listening on %s (method=%s)", ln.Addr(), s.spec.Name)

	// Close the listener when the context is canceled so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.drain()
				s.logf("shadowsocks: shut down cleanly")
				return nil
			default:
			}
			// Transient accept errors: brief backoff, keep serving.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.logf("shadowsocks: accept error: %v", err)
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

// drain waits for active relays to finish, bounded by shutdownDrain.
func (s *Server) drain() {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownDrain):
		s.logf("shadowsocks: drain timeout, %d relays may be cut", len(s.sem))
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	if !s.sourceAllowed(client.RemoteAddr()) {
		if s.metrics != nil {
			s.metrics.blockedByACL.Add(1)
		}
		s.logf("shadowsocks: reject %s (outside allowed_cidrs)", clientIPString(client.RemoteAddr()))
		return
	}

	// Concurrency gate. If we're at the cap, drop rather than queue — a
	// backlog on a tiny router just makes latency worse for everyone.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.logf("shadowsocks: at max conns, dropping %s", clientIPString(client.RemoteAddr()))
		return
	}

	timeout := s.opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	// Handshake (salt + header) must complete promptly.
	_ = client.SetReadDeadline(time.Now().Add(defaultHandshakeTO))

	reader, err := s.newDecryptReader(client)
	if err != nil {
		s.handshakeFail(err)
		return
	}
	target, err := readTargetAddr(reader)
	if err != nil {
		s.handshakeFail(err)
		return
	}

	// Clear the handshake deadline; the relay loop manages its own idle
	// timeouts from here.
	_ = client.SetReadDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	remote, err := s.dial(dialCtx, "tcp", target.String())
	cancel()
	if err != nil {
		if s.metrics != nil {
			s.metrics.dialErrors.Add(1)
		}
		s.logf("shadowsocks: dial %s failed: %v", target, err)
		return
	}
	defer remote.Close()

	writer, err := s.newEncryptWriter(client)
	if err != nil {
		s.logf("shadowsocks: writer init: %v", err)
		return
	}

	if s.metrics != nil {
		s.metrics.connectionsTotal.Add(1)
		s.metrics.activeConns.Add(1)
		defer s.metrics.activeConns.Add(-1)
	}
	s.logf("shadowsocks: relay %s <-> %s", clientIPString(client.RemoteAddr()), target)

	s.relay(client, remote, reader, writer, timeout)
}

// handshakeFail records a failed/rejected handshake. Replays are counted
// separately so operators can distinguish an attack from fat-fingered
// clients.
func (s *Server) handshakeFail(err error) {
	if s.metrics != nil {
		s.metrics.handshakeErrors.Add(1)
		if errors.Is(err, errReplay) {
			s.metrics.replayRejected.Add(1)
		}
	}
	// EOF is the normal case of a port scanner / probe; don't spam logs.
	if !errors.Is(err, io.EOF) {
		s.logf("shadowsocks: handshake failed: %v", err)
	}
}

// newDecryptReader reads the client's leading salt, enforces replay
// protection, derives the subkey, and returns an AEAD-decrypting reader over
// the remaining stream.
func (s *Server) newDecryptReader(client net.Conn) (io.Reader, error) {
	salt := make([]byte, s.spec.SaltSize())
	if _, err := io.ReadFull(client, salt); err != nil {
		return nil, err
	}
	if err := s.replay.check(salt); err != nil {
		return nil, err
	}
	sub, err := deriveSubkey(s.masterKey, salt, s.spec.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := s.spec.newAEAD(sub)
	if err != nil {
		return nil, err
	}
	return newAEADReader(client, aead), nil
}

// newEncryptWriter generates a fresh server-side salt, writes it to the
// client, and returns an AEAD-encrypting writer for the response stream.
func (s *Server) newEncryptWriter(client net.Conn) (io.Writer, error) {
	salt := make([]byte, s.spec.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := client.Write(salt); err != nil {
		return nil, err
	}
	sub, err := deriveSubkey(s.masterKey, salt, s.spec.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := s.spec.newAEAD(sub)
	if err != nil {
		return nil, err
	}
	return newAEADWriter(client, aead), nil
}

// relay pumps bytes both ways: decrypted client stream → remote, and remote
// → encrypted client stream. It closes when either side ends and records
// byte counters. Idle connections are reaped via per-copy deadlines.
func (s *Server) relay(client, remote net.Conn, decrypted io.Reader, encrypted io.Writer, timeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	var inCounter, outCounter *atomic.Uint64
	if s.metrics != nil {
		inCounter = &s.metrics.bytesIn
		outCounter = &s.metrics.bytesOut
	}

	// client → remote (bytes IN, from the proxy user's perspective)
	go func() {
		defer wg.Done()
		s.copyWithIdle(remote, decrypted, client, timeout, inCounter)
		// Signal EOF to the remote so it can flush and close.
		if tc, ok := remote.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = remote.SetReadDeadline(time.Now())
		}
	}()

	// remote → client (bytes OUT)
	go func() {
		defer wg.Done()
		s.copyWithIdle(encrypted, remote, remote, timeout, outCounter)
		// Unblock the other direction by tripping the client's read.
		_ = client.SetReadDeadline(time.Now())
	}()

	wg.Wait()
}

// copyWithIdle copies src→dst, refreshing an idle read deadline on the
// underlying connection deadlineConn before each read. It adds each written
// chunk to counter (if non-nil) as it goes, so /metrics reflects live
// throughput rather than only totals at relay teardown.
func (s *Server) copyWithIdle(dst io.Writer, src io.Reader, deadlineConn net.Conn, timeout time.Duration, counter *atomic.Uint64) {
	buf := make([]byte, 32*1024)
	for {
		if timeout > 0 {
			_ = deadlineConn.SetReadDeadline(time.Now().Add(timeout))
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if counter != nil && nw > 0 {
				counter.Add(uint64(nw))
			}
			if ew != nil || nw < nr {
				return
			}
		}
		if er != nil {
			return
		}
	}
}

// sourceAllowed reports whether a client remote address is permitted by
// AllowedCIDRs (empty list → allow all).
func (s *Server) sourceAllowed(remote net.Addr) bool {
	if len(s.opts.AllowedCIDRs) == 0 {
		return true
	}
	ip := ipFromAddr(remote)
	if ip == nil {
		return false
	}
	for _, n := range s.opts.AllowedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP
	default:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return net.ParseIP(a.String())
		}
		return net.ParseIP(host)
	}
}

func clientIPString(a net.Addr) string {
	if ip := ipFromAddr(a); ip != nil {
		return ip.String()
	}
	return "?"
}
