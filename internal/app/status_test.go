package app

import "testing"

func TestParseNFTAllowedClients(t *testing.T) {
	data := []byte(`{
		"nftables": [
			{"metainfo": {"json_schema_version": 1}},
			{"set": {
				"family": "inet",
				"name": "allowed_clients_v4",
				"elem": [
					{"elem": {"val": "1.2.3.4", "timeout": 15, "expires": 12}},
					{"elem": {"val": "2001:db8::1", "timeout": 15, "expires": "7s"}}
				]
			}}
		]
	}`)

	clients, err := parseNFTAllowedClients(data)
	if err != nil {
		t.Fatalf("parseNFTAllowedClients returned error: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d: %#v", len(clients), clients)
	}
	if clients[0].Address != "1.2.3.4" || clients[0].Expires != "12s" {
		t.Fatalf("unexpected first client: %#v", clients[0])
	}
	if clients[1].Address != "2001:db8::1" || clients[1].Expires != "7s" {
		t.Fatalf("unexpected second client: %#v", clients[1])
	}
}

func TestParseNFTAllowedClientsWithStringElem(t *testing.T) {
	data := []byte(`{
		"nftables": [
			{"set": {
				"family": "inet",
				"name": "allowed_clients_v4",
				"elem": [
					{"elem": "1.2.3.4", "timeout": 15, "expires": 12}
				]
			}}
		]
	}`)

	clients, err := parseNFTAllowedClients(data)
	if err != nil {
		t.Fatalf("parseNFTAllowedClients returned error: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d: %#v", len(clients), clients)
	}
	if clients[0].Address != "1.2.3.4" || clients[0].Expires != "12s" {
		t.Fatalf("unexpected client: %#v", clients[0])
	}
}
