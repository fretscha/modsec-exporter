// Package config loads the TOML site configuration for modsec-exporter.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config is the top-level structure of a TOML configuration file.
type Config struct {
	Sites []SiteConfig `toml:"site"`
}

// SiteConfig describes one Apache access+error log pair.
type SiteConfig struct {
	Name      string `toml:"name"`
	AccessLog string `toml:"access_log"`
	ErrorLog  string `toml:"error_log"`
}

// Load reads and parses the TOML file at path. Returns an error if the file
// cannot be read, fails to parse, or contains invalid site definitions.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	if _, err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if len(c.Sites) == 0 {
		return fmt.Errorf("at least one [[site]] entry is required")
	}
	seen := make(map[string]bool, len(c.Sites))
	for i, s := range c.Sites {
		if s.Name == "" {
			return fmt.Errorf("site[%d]: name is required", i)
		}
		if s.AccessLog == "" {
			return fmt.Errorf("site %q: access_log is required", s.Name)
		}
		if s.ErrorLog == "" {
			return fmt.Errorf("site %q: error_log is required", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate site name %q", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}
