package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger struct {
	mu     sync.Mutex
	l      *log.Logger
	w      io.Closer
	format string
	level  Level
}

func New(path, format string) (*Logger, error) {
	return NewWithLevel(path, "info", format)
}

func NewWithLevel(path, level, format string) (*Logger, error) {
	var writer io.Writer = os.Stdout
	var closer io.Closer
	if path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		writer = file
		closer = file
	}
	if format == "" {
		format = "text"
	}
	parsed, err := ParseLevel(level)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, err
	}
	return &Logger{l: log.New(writer, "", 0), w: closer, format: format, level: parsed}, nil
}

func (l *Logger) Close() error {
	if l.w != nil {
		return l.w.Close()
	}
	return nil
}

func (l *Logger) Event(event string, fields ...Field) { l.EventLevel(LevelInfo, event, fields...) }

func (l *Logger) Debug(event string, fields ...Field) { l.EventLevel(LevelDebug, event, fields...) }
func (l *Logger) Warn(event string, fields ...Field)  { l.EventLevel(LevelWarn, event, fields...) }
func (l *Logger) Error(event string, fields ...Field) { l.EventLevel(LevelError, event, fields...) }

func (l *Logger) EventLevel(level Level, event string, fields ...Field) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fields = append([]Field{F("level", level.String())}, fields...)
	if l.format == "json" {
		l.jsonEvent(event, fields...)
		return
	}
	l.textEvent(event, fields...)
}

func (l *Logger) textEvent(event string, fields ...Field) {
	var b strings.Builder
	b.WriteString(time.Now().Format(time.RFC3339))
	b.WriteByte(' ')
	b.WriteString(event)
	for _, field := range fields {
		if field.Key == "" {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(field.Key)
		b.WriteByte('=')
		b.WriteString(sanitizeField(field.Key, field.Value))
	}
	l.l.Print(b.String())
}

func (l *Logger) jsonEvent(event string, fields ...Field) {
	record := make(map[string]any, len(fields)+2)
	record["time"] = time.Now().Format(time.RFC3339)
	record["event"] = event
	for _, field := range fields {
		if field.Key == "" {
			continue
		}
		record[field.Key] = redactValue(field.Key, field.Value)
	}
	data, err := json.Marshal(record)
	if err != nil {
		l.textEvent(event, fields...)
		return
	}
	l.l.Print(string(data))
}

type Field struct {
	Key   string
	Value any
}

func F(key string, value any) Field {
	return Field{Key: key, Value: value}
}

func redactValue(key string, value any) any {
	if sensitiveKey(key) {
		return "[REDACTED]"
	}
	return normalize(value)
}

func sanitizeField(key string, value any) string {
	return sanitize(fmt.Sprint(redactValue(key, value)))
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	s = strings.ReplaceAll(s, "\t", "_")
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " ") {
		return `"` + strings.ReplaceAll(s, `"`, `'`) + `"`
	}
	return s
}

func normalize(v any) any {
	switch value := v.(type) {
	case error:
		return value.Error()
	case fmt.Stringer:
		return value.String()
	default:
		return value
	}
}

func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unsupported log level %q", s)
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

func sensitiveKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "secret") || strings.Contains(k, "token") || strings.Contains(k, "password") || strings.Contains(k, "payload") || k == "hmac" || k == "nonce" || k == "auth"
}
