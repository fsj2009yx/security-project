package config

import "github.com/yaml"

type Config struct {
	//服务监听端口
	Port int `yaml:"port"`
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	err := ReadYAML(path, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
