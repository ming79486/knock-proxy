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

type Logger struct {
	mu     sync.Mutex
	l      *log.Logger
	w      io.Closer
	format string
}

func New(path, format string) (*Logger, error) {
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
	return &Logger{l: log.New(writer, "", 0), w: closer, format: format}, nil
}

func (l *Logger) Close() error {
	if l.w != nil {
		return l.w.Close()
	}
	return nil
}

func (l *Logger) Event(event string, fields ...Field) {
	l.mu.Lock()
	defer l.mu.Unlock()

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
		b.WriteString(sanitize(fmt.Sprint(field.Value)))
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
		record[field.Key] = normalize(field.Value)
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
