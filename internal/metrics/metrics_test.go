package metrics

import (
	"strings"
	"testing"
)

func TestRegistryRender(t *testing.T) {
	r := New()
	r.Inc("knock_proxy_knock_accepted_total", nil)
	r.Add("knock_proxy_session_rx_bytes_total", nil, 42)
	r.Inc("knock_proxy_tcp_auth_rejected_total", Reason("invalid_hmac"))

	out := r.Render()
	for _, want := range []string{
		"knock_proxy_knock_accepted_total 1",
		"knock_proxy_session_rx_bytes_total 42",
		`knock_proxy_tcp_auth_rejected_total{reason="invalid_hmac"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
