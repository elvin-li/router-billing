package shadowsocks

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
)

// dialSS opens a Shadowsocks client connection to a running Server, sends the
// SOCKS5 target header, and returns a net.Conn-like pair of encrypting writer
// / decrypting reader wired to the same TCP socket. It intentionally reuses
// the package's own AEAD primitives so the test exercises the real framing.
//
// This lives in a _test.go file so it never ships in the production binary.
type ssClientConn struct {
	raw    net.Conn
	writer *aeadWriter
	reader *aeadReader
	spec   *CipherSpec
	key    []byte
}

func dialSS(serverAddr, method, password, targetHost string, targetPort int) (*ssClientConn, error) {
	spec, err := LookupCipher(method)
	if err != nil {
		return nil, err
	}
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	c := &ssClientConn{
		raw:  raw,
		spec: spec,
		key:  DeriveKey(password, spec.KeySize),
	}

	// Client → server salt + encrypting writer.
	salt := make([]byte, spec.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := raw.Write(salt); err != nil {
		raw.Close()
		return nil, err
	}
	sub, err := deriveSubkey(c.key, salt, spec.KeySize)
	if err != nil {
		raw.Close()
		return nil, err
	}
	aeadW, err := spec.newAEAD(sub)
	if err != nil {
		raw.Close()
		return nil, err
	}
	c.writer = newAEADWriter(raw, aeadW)

	// First encrypted payload MUST be the target address header.
	hdr, err := encodeTargetAddr(targetHost, targetPort)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := c.writer.Write(hdr); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// dialSSRaw returns the underlying connection and the client salt used, so a
// replay test can resend the exact same handshake bytes.
func dialSSRawHandshake(serverAddr, method, password, targetHost string, targetPort int) ([]byte, error) {
	spec, err := LookupCipher(method)
	if err != nil {
		return nil, err
	}
	key := DeriveKey(password, spec.KeySize)
	salt := make([]byte, spec.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sub, err := deriveSubkey(key, salt, spec.KeySize)
	if err != nil {
		return nil, err
	}
	aeadW, err := spec.newAEAD(sub)
	if err != nil {
		return nil, err
	}
	var buf bytesBuffer
	w := newAEADWriter(&buf, aeadW)
	hdr, err := encodeTargetAddr(targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte("PING")); err != nil {
		return nil, err
	}
	out := append([]byte{}, salt...)
	out = append(out, buf.Bytes()...)
	return out, nil
}

func (c *ssClientConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *ssClientConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		// Read the server's salt first, then build the decrypting reader.
		salt := make([]byte, c.spec.SaltSize())
		if _, err := io.ReadFull(c.raw, salt); err != nil {
			return 0, err
		}
		sub, err := deriveSubkey(c.key, salt, c.spec.KeySize)
		if err != nil {
			return 0, err
		}
		aeadR, err := c.spec.newAEAD(sub)
		if err != nil {
			return 0, err
		}
		c.reader = newAEADReader(c.raw, aeadR)
	}
	return c.reader.Read(p)
}

func (c *ssClientConn) Close() error { return c.raw.Close() }

func (c *ssClientConn) CloseWrite() error {
	if tc, ok := c.raw.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return fmt.Errorf("not a tcp conn")
}

// bytesBuffer is a tiny io.Writer accumulator (avoids importing bytes just
// for the handshake replay helper's scratch space).
type bytesBuffer struct{ b []byte }

func (bb *bytesBuffer) Write(p []byte) (int, error) {
	bb.b = append(bb.b, p...)
	return len(p), nil
}
func (bb *bytesBuffer) Bytes() []byte { return bb.b }
