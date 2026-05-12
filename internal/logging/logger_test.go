package logging

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{l: log.New(&buf, "", 0), format: "json"}
	logger.Event("knock accepted", F("src", "1.2.3.4"), F("rx", 10))

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v; data=%s", err, buf.String())
	}
	if got["event"] != "knock accepted" {
		t.Fatalf("event mismatch: %v", got["event"])
	}
	if got["src"] != "1.2.3.4" {
		t.Fatalf("src mismatch: %v", got["src"])
	}
}

func TestLoggerLevelFilters(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{l: log.New(&buf, "", 0), format: "text", level: LevelWarn}
	logger.Event("info event")
	logger.Warn("warn event")
	out := buf.String()
	if strings.Contains(out, "info event") {
		t.Fatalf("info event should be filtered: %s", out)
	}
	if !strings.Contains(out, "warn event") {
		t.Fatalf("warn event missing: %s", out)
	}
}

func TestLoggerRedactsSensitiveFields(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{l: log.New(&buf, "", 0), format: "text", level: LevelDebug}
	logger.Debug("diagnostic", F("secret", "super-secret"), F("token", "abc"), F("payload", "raw-auth-frame"), F("client_id", "client-001"))
	out := buf.String()
	for _, leak := range []string{"super-secret", "abc", "raw-auth-frame"} {
		if strings.Contains(out, leak) {
			t.Fatalf("sensitive value leaked in log: %s", out)
		}
	}
	if !strings.Contains(out, "client-001") {
		t.Fatalf("non-sensitive field missing: %s", out)
	}
}
