package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	UDPSeqMethod      = "udp-seq"
	UDPSeqInfoPrefix  = "knock-proxy/udp-seq/v1"
	UDPSeqNonceBytes  = 16
	UDPSeqDefaultSlot = 30 * time.Second
)

type UDPSeqPart struct {
	Version       int    `json:"version"`
	Method        string `json:"method"`
	ClientID      string `json:"client_id"`
	ProtectedPort int    `json:"protected_port"`
	TimeSlot      int64  `json:"time_slot"`
	Nonce         string `json:"nonce"`
	Index         int    `json:"index"`
	Total         int    `json:"total"`
	Tag           string `json:"tag"`
	FinalMAC      string `json:"final_mac,omitempty"`
}

func NewUDPSeqParts(clientID string, secret []byte, protectedPort int, now time.Time, slotSeconds, total int) ([]UDPSeqPart, error) {
	if total < 2 || total > 5 {
		return nil, fmt.Errorf("udp-seq length must be between 2 and 5")
	}
	raw := make([]byte, UDPSeqNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	nonce := base64.RawStdEncoding.EncodeToString(raw)
	return BuildUDPSeqParts(clientID, secret, protectedPort, now, slotSeconds, total, raw, nonce)
}

func BuildUDPSeqParts(clientID string, secret []byte, protectedPort int, now time.Time, slotSeconds, total int, nonceRaw []byte, nonce string) ([]UDPSeqPart, error) {
	if total < 2 || total > 5 {
		return nil, fmt.Errorf("udp-seq length must be between 2 and 5")
	}
	if slotSeconds <= 0 {
		slotSeconds = 30
	}
	slot := now.Unix() / int64(slotSeconds)
	key := udpSeqKey(secret, nonceRaw, clientID, protectedPort, slot)
	parts := make([]UDPSeqPart, total)
	meta := sha256.New()
	for i := range parts {
		tag := udpSeqTag(key, "part", i, total, protectedPort, nil)
		parts[i] = UDPSeqPart{Version: Version, Method: UDPSeqMethod, ClientID: clientID, ProtectedPort: protectedPort, TimeSlot: slot, Nonce: nonce, Index: i, Total: total, Tag: tag}
		fmt.Fprintf(meta, "%d/%d/%d/%s/%s;", i, total, protectedPort, UDPSeqMethod, tag)
	}
	parts[total-1].FinalMAC = udpSeqTag(key, "final", total-1, total, protectedPort, meta.Sum(nil))
	return parts, nil
}

func ValidateUDPSeqPart(part UDPSeqPart, secret []byte, protectedPort int, now time.Time, slotSeconds, total int) error {
	if part.Version != Version {
		return fmt.Errorf("unsupported udp-seq version %d", part.Version)
	}
	if part.Method != UDPSeqMethod {
		return fmt.Errorf("udp-seq method mismatch")
	}
	if part.ClientID == "" || part.Nonce == "" {
		return fmt.Errorf("empty udp-seq client_id or nonce")
	}
	if part.ProtectedPort != protectedPort {
		return fmt.Errorf("udp-seq protected_port mismatch")
	}
	if part.Total != total || part.Total < 2 || part.Total > 5 || part.Index < 0 || part.Index >= part.Total {
		return fmt.Errorf("invalid udp-seq index or total")
	}
	if slotSeconds <= 0 {
		slotSeconds = 30
	}
	current := now.Unix() / int64(slotSeconds)
	if part.TimeSlot < current-1 || part.TimeSlot > current+1 {
		return ErrExpiredTimestamp
	}
	raw, err := base64.RawStdEncoding.DecodeString(part.Nonce)
	if err != nil || len(raw) != UDPSeqNonceBytes {
		return fmt.Errorf("invalid udp-seq nonce")
	}
	key := udpSeqKey(secret, raw, part.ClientID, protectedPort, part.TimeSlot)
	expected := udpSeqTag(key, "part", part.Index, part.Total, protectedPort, nil)
	got, err := hex.DecodeString(part.Tag)
	if err != nil {
		return ErrInvalidHMAC
	}
	want, _ := hex.DecodeString(expected)
	if !hmac.Equal(got, want) {
		return ErrInvalidHMAC
	}
	return nil
}

func ValidateUDPSeqFinal(parts []UDPSeqPart, secret []byte, protectedPort int) error {
	if len(parts) == 0 {
		return fmt.Errorf("empty udp-seq parts")
	}
	last := parts[len(parts)-1]
	if last.FinalMAC == "" {
		return ErrInvalidHMAC
	}
	raw, err := base64.RawStdEncoding.DecodeString(last.Nonce)
	if err != nil || len(raw) != UDPSeqNonceBytes {
		return fmt.Errorf("invalid udp-seq nonce")
	}
	key := udpSeqKey(secret, raw, last.ClientID, protectedPort, last.TimeSlot)
	meta := sha256.New()
	for _, part := range parts {
		fmt.Fprintf(meta, "%d/%d/%d/%s/%s;", part.Index, part.Total, protectedPort, UDPSeqMethod, part.Tag)
	}
	expected := udpSeqTag(key, "final", len(parts)-1, len(parts), protectedPort, meta.Sum(nil))
	got, err := hex.DecodeString(last.FinalMAC)
	if err != nil {
		return ErrInvalidHMAC
	}
	want, _ := hex.DecodeString(expected)
	if !hmac.Equal(got, want) {
		return ErrInvalidHMAC
	}
	return nil
}

func udpSeqKey(secret, nonceRaw []byte, clientID string, protectedPort int, slot int64) []byte {
	info := []byte(fmt.Sprintf("%s|%s|%d|%d|%s", UDPSeqInfoPrefix, clientID, protectedPort, slot, UDPSeqMethod))
	return hkdfSHA256(secret, nonceRaw, info, sha256.Size)
}

func udpSeqTag(key []byte, domain string, index, total, protectedPort int, digest []byte) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s|%d|%d|%d|%s", domain, index, total, protectedPort, UDPSeqMethod)
	if len(digest) > 0 {
		mac.Write([]byte{'|'})
		mac.Write(digest)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func hkdfSHA256(secret, salt, info []byte, outLen int) []byte {
	prkMac := hmac.New(sha256.New, salt)
	prkMac.Write(secret)
	prk := prkMac.Sum(nil)
	var out, prev []byte
	counter := byte(1)
	for len(out) < outLen {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{counter})
		prev = m.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:outLen]
}

type SYNSeqPart struct {
	Port   int
	Fields SYNFields
}

func ComputeSYNSeqParts(secret []byte, clientID string, protectedPort int, slot int64, total int) []SYNSeqPart {
	return computeSYNSeqParts(secret, clientID, protectedPort, slot, total, false)
}

func computeLegacySYNSeqParts(secret []byte, clientID string, protectedPort int, slot int64, total int) []SYNSeqPart {
	return computeSYNSeqParts(secret, clientID, protectedPort, slot, total, true)
}

func computeSYNSeqParts(secret []byte, clientID string, protectedPort int, slot int64, total int, legacyRandomPorts bool) []SYNSeqPart {
	if total < 2 || total > 5 {
		total = 3
	}
	out := make([]SYNSeqPart, total)
	for i := range out {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte("knock-proxy/tcp-syn-seq/v1"))
		writeString(mac, clientID)
		writeUint16(mac, uint16(protectedPort))
		writeInt64(mac, slot)
		writeUint16(mac, uint16(i))
		tag := mac.Sum(nil)
		port := protectedPort
		if legacyRandomPorts {
			port = 1024 + int(binary.BigEndian.Uint16(tag[0:2])%64511)
		}
		window := binary.BigEndian.Uint16(tag[6:8])
		if window == 0 {
			window = 1
		}
		out[i] = SYNSeqPart{Port: port, Fields: SYNFields{Sequence: binary.BigEndian.Uint32(tag[2:6]), Window: window, Timestamp: binary.BigEndian.Uint32(tag[8:12])}}
	}
	return out
}

func VerifySYNSeqPart(fields SYNFields, dstPort int, clients []ClientSecret, protectedPort int, now time.Time, slotSeconds, total, index int) (string, int64, bool) {
	if slotSeconds <= 0 {
		slotSeconds = 30
	}
	current := now.Unix() / int64(slotSeconds)
	for _, client := range clients {
		for _, delta := range []int64{-1, 0, 1} {
			slot := current + delta
			if synSeqPartMatches(ComputeSYNSeqParts(client.Secret, client.ClientID, protectedPort, slot, total), index, dstPort, fields) || synSeqPartMatches(computeLegacySYNSeqParts(client.Secret, client.ClientID, protectedPort, slot, total), index, dstPort, fields) {
				return client.ClientID, slot, true
			}
		}
	}
	return "", 0, false
}

func synSeqPartMatches(parts []SYNSeqPart, index, dstPort int, fields SYNFields) bool {
	return index >= 0 && index < len(parts) && parts[index].Port == dstPort && parts[index].Fields == fields
}
