package shadowsocks

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// deriveSubkey computes the per-connection AEAD key from the master key and
// the connection salt via HKDF-SHA1 (the reference "ss-subkey" derivation).
func deriveSubkey(masterKey, salt []byte, keyLen int) ([]byte, error) {
	sub := make([]byte, keyLen)
	r := hkdf.New(shaNew, masterKey, salt, subkeyInfo)
	if _, err := io.ReadFull(r, sub); err != nil {
		return nil, err
	}
	return sub, nil
}

// increment does a little-endian +1 on the nonce buffer in place. AEAD
// chunks use a 12-byte counter that starts at zero and bumps after every
// seal/open, exactly matching the reference implementation.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// aeadWriter encrypts a plaintext stream into Shadowsocks AEAD chunks.
//
// Each Write is split into <=maxPayloadChunk pieces; each piece is emitted as
// a 2-byte length chunk (encrypted+tagged) followed by the payload chunk
// (encrypted+tagged). The leading connection salt must be written to the
// wire separately before the first chunk (the server/client handshake does
// this).
type aeadWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
	buf   []byte // scratch: length header + payload + tags
}

func newAEADWriter(w io.Writer, aead cipher.AEAD) *aeadWriter {
	return &aeadWriter{
		w:     w,
		aead:  aead,
		nonce: make([]byte, aead.NonceSize()),
		buf:   make([]byte, 2+aead.Overhead()+maxPayloadChunk+aead.Overhead()),
	}
}

func (aw *aeadWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPayloadChunk {
			n = maxPayloadChunk
		}
		if err := aw.writeChunk(p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (aw *aeadWriter) writeChunk(plain []byte) error {
	// [encrypted length(2) + tag]
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(plain)))
	lenCipher := aw.aead.Seal(aw.buf[:0], aw.nonce, lenBuf[:], nil)
	increment(aw.nonce)

	// [encrypted payload + tag]
	off := len(lenCipher)
	payCipher := aw.aead.Seal(aw.buf[off:off], aw.nonce, plain, nil)
	increment(aw.nonce)

	end := off + len(payCipher)
	_, err := aw.w.Write(aw.buf[:end])
	return err
}

// aeadReader decrypts a Shadowsocks AEAD chunk stream back into plaintext.
// The caller is responsible for having consumed the leading salt and
// constructed the AEAD with the derived subkey before the first Read.
type aeadReader struct {
	r       io.Reader
	aead    cipher.AEAD
	nonce   []byte
	leftraw []byte // decrypted-but-unread plaintext
	lenBuf  []byte // scratch for the 2-byte length chunk
	payBuf  []byte // scratch for a full payload chunk
}

func newAEADReader(r io.Reader, aead cipher.AEAD) *aeadReader {
	overhead := aead.Overhead()
	return &aeadReader{
		r:      r,
		aead:   aead,
		nonce:  make([]byte, aead.NonceSize()),
		lenBuf: make([]byte, 2+overhead),
		payBuf: make([]byte, maxPayloadChunk+overhead),
	}
}

func (ar *aeadReader) Read(p []byte) (int, error) {
	if len(ar.leftraw) == 0 {
		if err := ar.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, ar.leftraw)
	ar.leftraw = ar.leftraw[n:]
	return n, nil
}

// readChunk pulls exactly one length+payload chunk pair off the wire and
// stashes the decrypted payload in leftraw.
func (ar *aeadReader) readChunk() error {
	if _, err := io.ReadFull(ar.r, ar.lenBuf); err != nil {
		return err
	}
	lenPlain, err := ar.aead.Open(ar.lenBuf[:0], ar.nonce, ar.lenBuf, nil)
	if err != nil {
		return err
	}
	increment(ar.nonce)
	size := int(binary.BigEndian.Uint16(lenPlain))
	if size == 0 || size > maxPayloadChunk {
		return errBadLength
	}

	need := size + ar.aead.Overhead()
	if _, err := io.ReadFull(ar.r, ar.payBuf[:need]); err != nil {
		return err
	}
	payPlain, err := ar.aead.Open(ar.payBuf[:0], ar.nonce, ar.payBuf[:need], nil)
	if err != nil {
		return err
	}
	increment(ar.nonce)
	ar.leftraw = payPlain
	return nil
}
