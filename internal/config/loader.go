package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and unmarshals a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Default returns a Config populated with sensible defaults.
func Default() *Config {
	return &Config{
		Replay: ReplayConfig{
			Mode:    "sequential",
			Speed:   1.0,
			Workers: 4,
		},
		Mutations: MutationConfig{
			PreserveSessions: true,
		},
		Metrics: MetricsConfig{
			Enabled:        true,
			ReportInterval: "1s",
			Output:         "stdout",
		},
	}
}
