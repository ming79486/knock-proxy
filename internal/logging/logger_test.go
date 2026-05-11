package logging

import (
	"bytes"
	"encoding/json"
	"log"
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
