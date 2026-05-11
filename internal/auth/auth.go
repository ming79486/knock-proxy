package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	Version          = 1
	AuthPurpose      = "tcp-auth"
	SYNKnockPurpose  = "syn-knock"
	MaxAuthFrameSize = 4096
	NonceBytes       = 24
)

type Frame struct {
	Version    int    `json:"version"`
	ClientID   string `json:"client_id"`
	Method     string `json:"method,omitempty"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Encryption bool   `json:"encryption"`
	HMAC       string `json:"hmac"`
}

type ClientSecret struct {
	ClientID string
	Secret   []byte
}

func NewFrame(clientID string, secret []byte, serverPort int, encryption bool, now time.Time) (Frame, error) {
	nonce, err := randomNonce()
	if err != nil {
		return Frame{}, err
	}

	frame := Frame{
		Version:    Version,
		ClientID:   clientID,
		Timestamp:  now.Unix(),
		Nonce:      nonce,
		Encryption: encryption,
	}
	frame.HMAC = ComputeTCPAuthHMAC(secret, frame.Version, frame.ClientID, frame.Timestamp, frame.Nonce, serverPort, frame.Encryption)
	return frame, nil
}

func NewKnockFrame(clientID string, secret []byte, serverPort int, method string, now time.Time) (Frame, error) {
	nonce, err := randomNonce()
	if err != nil {
		return Frame{}, err
	}
	frame := Frame{
		Version:   Version,
		ClientID:  clientID,
		Method:    method,
		Timestamp: now.Unix(),
		Nonce:     nonce,
	}
	frame.HMAC = ComputeKnockHMAC(secret, frame.Version, frame.ClientID, frame.Method, frame.Timestamp, frame.Nonce, serverPort)
	return frame, nil
}

func WriteFrame(w io.Writer, frame Frame) error {
	data, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(data)+1 > MaxAuthFrameSize {
		return errors.New("auth frame too large")
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	line := make([]byte, 0, 512)
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			line = append(line, one[0])
			if len(line) > MaxAuthFrameSize {
				return Frame{}, errors.New("auth frame too large")
			}
		}
		if err != nil {
			return Frame{}, err
		}
	}

	var frame Frame
	if err := json.Unmarshal(line, &frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func ValidateFrame(frame Frame, secret []byte, serverPort int, encryption bool, now time.Time, window time.Duration) error {
	if frame.Version != Version {
		return fmt.Errorf("unsupported auth version %d", frame.Version)
	}
	if frame.ClientID == "" {
		return errors.New("empty client_id")
	}
	if frame.Nonce == "" {
		return errors.New("empty nonce")
	}
	if frame.Encryption != encryption {
		return errors.New("encryption flag mismatch")
	}
	age := now.Sub(time.Unix(frame.Timestamp, 0))
	if age < -window || age > window {
		return ErrExpiredTimestamp
	}

	expected := ComputeTCPAuthHMAC(secret, frame.Version, frame.ClientID, frame.Timestamp, frame.Nonce, serverPort, frame.Encryption)
	got, err := hex.DecodeString(frame.HMAC)
	if err != nil {
		return ErrInvalidHMAC
	}
	want, _ := hex.DecodeString(expected)
	if !hmac.Equal(got, want) {
		return ErrInvalidHMAC
	}
	return nil
}

func ValidateKnockFrame(frame Frame, secret []byte, serverPort int, method string, now time.Time, window time.Duration) error {
	if frame.Version != Version {
		return fmt.Errorf("unsupported knock version %d", frame.Version)
	}
	if frame.ClientID == "" {
		return errors.New("empty client_id")
	}
	if frame.Nonce == "" {
		return errors.New("empty nonce")
	}
	if frame.Method != method {
		return errors.New("knock method mismatch")
	}
	age := now.Sub(time.Unix(frame.Timestamp, 0))
	if age < -window || age > window {
		return ErrExpiredTimestamp
	}
	expected := ComputeKnockHMAC(secret, frame.Version, frame.ClientID, frame.Method, frame.Timestamp, frame.Nonce, serverPort)
	got, err := hex.DecodeString(frame.HMAC)
	if err != nil {
		return ErrInvalidHMAC
	}
	want, _ := hex.DecodeString(expected)
	if !hmac.Equal(got, want) {
		return ErrInvalidHMAC
	}
	return nil
}

func ComputeTCPAuthHMAC(secret []byte, version int, clientID string, timestamp int64, nonce string, serverPort int, encryption bool) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(AuthPurpose))
	writeUint16(mac, uint16(version))
	writeString(mac, clientID)
	writeInt64(mac, timestamp)
	writeString(mac, nonce)
	writeUint16(mac, uint16(serverPort))
	if encryption {
		mac.Write([]byte{1})
	} else {
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func ComputeKnockHMAC(secret []byte, version int, clientID, method string, timestamp int64, nonce string, serverPort int) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("knock-auth"))
	writeUint16(mac, uint16(version))
	writeString(mac, clientID)
	writeString(mac, method)
	writeInt64(mac, timestamp)
	writeString(mac, nonce)
	writeUint16(mac, uint16(serverPort))
	return hex.EncodeToString(mac.Sum(nil))
}

type SYNFields struct {
	Sequence  uint32
	Window    uint16
	Timestamp uint32
}

func ComputeSYNFields(secret []byte, clientID string, serverPort int, slot int64) SYNFields {
	tag := ComputeSYNTag(secret, clientID, serverPort, slot)
	window := binary.BigEndian.Uint16(tag[4:6])
	if window == 0 {
		window = 1
	}
	return SYNFields{
		Sequence:  binary.BigEndian.Uint32(tag[0:4]),
		Window:    window,
		Timestamp: binary.BigEndian.Uint32(tag[6:10]),
	}
}

func ComputeSYNTag(secret []byte, clientID string, serverPort int, slot int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(SYNKnockPurpose))
	writeString(mac, clientID)
	writeUint16(mac, uint16(serverPort))
	writeInt64(mac, slot)
	return mac.Sum(nil)
}

func VerifySYNFields(fields SYNFields, clients []ClientSecret, serverPort int, now time.Time, window time.Duration) (string, bool) {
	slotSize := int64(window.Seconds())
	if slotSize <= 0 {
		slotSize = 30
	}
	current := now.Unix() / slotSize
	for _, client := range clients {
		for _, delta := range []int64{-1, 0, 1} {
			expected := ComputeSYNFields(client.Secret, client.ClientID, serverPort, current+delta)
			if expected == fields {
				return client.ClientID, true
			}
		}
	}
	return "", false
}

func SlotFor(t time.Time, window time.Duration) int64 {
	slotSize := int64(window.Seconds())
	if slotSize <= 0 {
		slotSize = 30
	}
	return t.Unix() / slotSize
}

func randomNonce() (string, error) {
	raw := make([]byte, NonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(raw), nil
}

func writeString(w io.Writer, s string) {
	writeUint16(w, uint16(len(s)))
	_, _ = w.Write([]byte(s))
}

func writeUint16(w io.Writer, v uint16) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	_, _ = w.Write(buf[:])
}

func writeInt64(w io.Writer, v int64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	_, _ = w.Write(buf[:])
}

var (
	ErrInvalidHMAC      = errors.New("invalid_hmac")
	ErrExpiredTimestamp = errors.New("expired_timestamp")
)
