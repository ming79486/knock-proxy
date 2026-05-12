package app

import "time"

type ClientOptions struct {
	ConfigPath string
	Listen     string
	ServerAddr string
	ClientID   string
	Secret     string
	SecretFile string
	Method     string
}

type ServerOptions struct {
	ConfigPath      string
	Listen          string
	Upstream        string
	FirewallBackend string
	AllowSeconds    int
	DryRun          bool
}

type KnockOptions struct {
	ServerAddr       string
	ClientID         string
	Secret           string
	SecretFile       string
	Method           string
	UDPKnockPort     int
	ProtectedTCPPort int
	WaitOpen         bool
	WaitOpenTimeout  time.Duration
}

type ProbeOptions struct {
	ConfigPath string
	Payload    string
	KnockOnly  bool
}

type DoctorOptions struct {
	ConfigPath string
}

type StatusOptions struct {
	ConfigPath string
}

type InitOptions struct {
	Kind       string
	Listen     string
	ServerAddr string
	Upstream   string
	ClientID   string
	SecretFile string
	OutDir     string
	Platform   string
	Method     string
}
