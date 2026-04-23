package config

import (
	"encoding/json"
	"errors"
	"os"

	"security-project/common/krb"
)

type ClientEntry struct {
	ID       string `json:"id"`
	KcPath   string `json:"kc_path"`
	KcHex    string `json:"kc_hex,omitempty"`
	CertPath string `json:"cert_path"`
	ADc      uint32 `json:"adc,omitempty"`
}

type Config struct {
	NodeID            string        `json:"node_id"`
	ListenHost        string        `json:"listen_host"`
	ListenPort        int           `json:"listen_port"`
	WebUIHost         string        `json:"webui_host"`
	WebUIPort         int           `json:"webui_port"`
	ThreadPoolSize    int           `json:"thread_pool_size"`
	AntiReplayWindow  int           `json:"anti_replay_window_size"`
	TicketLifetimeSec uint32        `json:"ticket_lifetime_sec"`
	CertPath          string        `json:"cert_path"`
	PrivKeyPath       string        `json:"privkey_path"`
	LogFile           string        `json:"log_file"`
	SecurityLogFile   string        `json:"security_log_file"`
	KtgsPath          string        `json:"k_tgs_path"`
	ClientDB          []ClientEntry `json:"client_db"`
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
		NodeID:            "AS",
		ListenHost:        "0.0.0.0",
		ListenPort:        8881,
		WebUIHost:         "0.0.0.0",
		WebUIPort:         9881,
		ThreadPoolSize:    8,
		AntiReplayWindow:  1024,
		TicketLifetimeSec: 28800,
		CertPath:          "./certs/as_cert.json",
		PrivKeyPath:       "./keys/as_priv.json",
		LogFile:           "./logs/as.log",
		SecurityLogFile:   "./logs/security.log",
		KtgsPath:          "./keys/k_tgs.bin",
		ClientDB: []ClientEntry{
			{ID: "CLIENT_1", KcPath: "./keys/kc_client1.bin", CertPath: "./certs/client1_cert.json"},
			{ID: "CLIENT_2", KcPath: "./keys/kc_client2.bin", CertPath: "./certs/client2_cert.json"},
			{ID: "CLIENT_3", KcPath: "./keys/kc_client3.bin", CertPath: "./certs/client3_cert.json"},
			{ID: "CLIENT_4", KcPath: "./keys/kc_client4.bin", CertPath: "./certs/client4_cert.json"},
		},
	}
}

func (c *Config) normalize() error {
	if c.NodeID == "" {
		c.NodeID = "AS"
	}
	if c.ListenPort <= 0 {
		c.ListenPort = 8881
	}
	if c.WebUIPort <= 0 {
		c.WebUIPort = 9881
	}
	if c.ThreadPoolSize <= 0 {
		c.ThreadPoolSize = 8
	}
	if c.AntiReplayWindow <= 0 {
		c.AntiReplayWindow = 1024
	}
	if c.TicketLifetimeSec == 0 {
		c.TicketLifetimeSec = 28800
	}
	if c.KtgsPath == "" {
		c.KtgsPath = "./keys/k_tgs.bin"
	}
	if len(c.ClientDB) == 0 {
		return errors.New("client_db is empty")
	}
	_ = krb.EnsureDir("./logs")
	_ = krb.EnsureDir("./keys")
	_ = krb.EnsureDir("./certs")
	return nil
}
