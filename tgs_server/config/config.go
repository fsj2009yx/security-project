package config

import (
	"encoding/json"
	"errors"
	"os"

	"security-project/common/krb"
)

type ServiceEntry struct {
	IDV    string `json:"id_v"`
	KVPath string `json:"kv_path"`
	KVHex  string `json:"kv_hex,omitempty"`
	Addr   string `json:"addr,omitempty"`
}

type Config struct {
	NodeID            string         `json:"node_id"`
	ListenHost        string         `json:"listen_host"`
	ListenPort        int            `json:"listen_port"`
	WebUIHost         string         `json:"webui_host"`
	WebUIPort         int            `json:"webui_port"`
	TicketLifetimeSec uint32         `json:"ticket_lifetime_sec"`
	CertPath          string         `json:"cert_path"`
	PrivKeyPath       string         `json:"privkey_path"`
	LogFile           string         `json:"log_file"`
	SecurityLogFile   string         `json:"security_log_file"`
	KTGSPath          string         `json:"k_tgs_path"`
	ServiceDB         []ServiceEntry `json:"services"`
}

func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	if path == "" {
		path = "config.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, nil
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		NodeID:            "TGS",
		ListenHost:        "0.0.0.0",
		ListenPort:        8882,
		WebUIHost:         "0.0.0.0",
		WebUIPort:         9882,
		TicketLifetimeSec: 28800,
		CertPath:          "./certs/tgs_cert.json",
		PrivKeyPath:       "./keys/tgs_priv.json",
		LogFile:           "./logs/tgs.log",
		SecurityLogFile:   "./logs/security.log",
		KTGSPath:          "./keys/k_tgs.bin",
		ServiceDB: []ServiceEntry{
			{IDV: "verify_server", KVPath: "./keys/k_v.bin", Addr: "127.0.0.1:8883"},
		},
	}
}

func (c *Config) normalize() error {
	if c.NodeID == "" {
		c.NodeID = "TGS"
	}
	if c.ListenPort <= 0 {
		c.ListenPort = 8882
	}
	if c.WebUIPort <= 0 {
		c.WebUIPort = 9882
	}
	if c.TicketLifetimeSec == 0 {
		c.TicketLifetimeSec = 28800
	}
	if c.KTGSPath == "" {
		c.KTGSPath = "./keys/k_tgs.bin"
	}
	if len(c.ServiceDB) == 0 {
		return errors.New("services is empty")
	}
	_ = krb.EnsureDir("./logs")
	_ = krb.EnsureDir("./keys")
	_ = krb.EnsureDir("./certs")
	return nil
}
