package secure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	maxPlainFrame  = 16 * 1024
	maxCipherFrame = maxPlainFrame + chacha20poly1305.Overhead
)

type Role string

const (
	ClientRole Role = "client"
	ServerRole Role = "server"
)

type Conn struct {
	raw net.Conn

	readAEAD  cipherAEAD
	writeAEAD cipherAEAD

	readMu   sync.Mutex
	writeMu  sync.Mutex
	readBuf  []byte
	readSeq  uint64
	writeSeq uint64
	writeEOF bool
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func Wrap(conn net.Conn, secret []byte, clientID, authNonce string, serverPort int, role Role) (net.Conn, error) {
	c2s, err := chacha20poly1305.New(deriveKey(secret, clientID, authNonce, serverPort, "c2s"))
	if err != nil {
		return nil, err
	}
	s2c, err := chacha20poly1305.New(deriveKey(secret, clientID, authNonce, serverPort, "s2c"))
	if err != nil {
		return nil, err
	}

	c := &Conn{raw: conn}
	switch role {
	case ClientRole:
		c.writeAEAD = c2s
		c.readAEAD = s2c
	case ServerRole:
		c.writeAEAD = s2c
		c.readAEAD = c2s
	default:
		return nil, errors.New("invalid secure transport role")
	}
	return c, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeEOF {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlainFrame {
			chunk = p[:maxPlainFrame]
		}
		if err := c.writeFrame(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *Conn) Close() error {
	return c.raw.Close()
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return nil
	}
	c.writeEOF = true
	var header [4]byte
	_, err := c.raw.Write(header[:])
	return err
}

func (c *Conn) CloseRead() error {
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.raw.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

func (c *Conn) readFrame() error {
	var header [4]byte
	if _, err := io.ReadFull(c.raw, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return io.EOF
	}
	if size > maxCipherFrame {
		return errors.New("invalid encrypted frame size")
	}
	ciphertext := make([]byte, int(size))
	if _, err := io.ReadFull(c.raw, ciphertext); err != nil {
		return err
	}
	plain, err := c.readAEAD.Open(nil, makeNonce(c.readSeq), ciphertext, nil)
	if err != nil {
		return err
	}
	c.readSeq++
	c.readBuf = plain
	return nil
}

func (c *Conn) writeFrame(plain []byte) error {
	ciphertext := c.writeAEAD.Seal(nil, makeNonce(c.writeSeq), plain, nil)
	c.writeSeq++
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(ciphertext)))
	if _, err := c.raw.Write(header[:]); err != nil {
		return err
	}
	_, err := c.raw.Write(ciphertext)
	return err
}

func deriveKey(secret []byte, clientID, authNonce string, serverPort int, direction string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("transport-key"))
	writeString(mac, clientID)
	writeString(mac, authNonce)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(serverPort))
	mac.Write(port[:])
	writeString(mac, direction)
	return mac.Sum(nil)
}

func makeNonce(seq uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func writeString(w io.Writer, s string) {
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(s)))
	_, _ = w.Write(size[:])
	_, _ = w.Write([]byte(s))
}
