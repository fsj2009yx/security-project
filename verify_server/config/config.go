package config

import (
	"encoding/json"
	"errors"
	"os"

	"security-project/common/krb"
)

type ClientCertEntry struct {
	ID       string `json:"id"`
	CertPath string `json:"cert_path"`
	Addr     string `json:"addr,omitempty"`
}

type Config struct {
	NodeID          string            `json:"node_id"`
	ListenHost      string            `json:"listen_host"`
	ListenPort      int               `json:"listen_port"`
	WebUIHost       string            `json:"webui_host"`
	WebUIPort       int               `json:"webui_port"`
	CertPath        string            `json:"cert_path"`
	PrivKeyPath     string            `json:"privkey_path"`
	LogFile         string            `json:"log_file"`
	SecurityLogFile string            `json:"security_log_file"`
	KVPath          string            `json:"k_v_path"`
	CLIWhitelist    []string          `json:"cli_whitelist"`
	ClientDB        []ClientCertEntry `json:"client_db"`
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
		NodeID:          "verify_server",
		ListenHost:      "0.0.0.0",
		ListenPort:      8883,
		WebUIHost:       "0.0.0.0",
		WebUIPort:       9883,
		CertPath:        "./certs/v_cert.json",
		PrivKeyPath:     "./keys/v_priv.json",
		LogFile:         "./logs/v.log",
		SecurityLogFile: "./logs/security.log",
		KVPath:          "./keys/k_v.bin",
		ClientDB: []ClientCertEntry{
			{ID: "CLIENT_1", CertPath: "./certs/client1_cert.json"},
			{ID: "CLIENT_2", CertPath: "./certs/client2_cert.json"},
			{ID: "CLIENT_3", CertPath: "./certs/client3_cert.json"},
			{ID: "CLIENT_4", CertPath: "./certs/client4_cert.json"},
		},
	}
}

func (c *Config) normalize() error {
	if c.NodeID == "" {
		c.NodeID = "verify_server"
	}
	if c.ListenPort <= 0 {
		c.ListenPort = 8883
	}
	if c.WebUIPort <= 0 {
		c.WebUIPort = 9883
	}
	if c.KVPath == "" {
		c.KVPath = "./keys/k_v.bin"
	}
	if len(c.ClientDB) == 0 {
		return errors.New("client_db is empty")
	}
	_ = krb.EnsureDir("./logs")
	_ = krb.EnsureDir("./keys")
	_ = krb.EnsureDir("./certs")
	return nil
}
