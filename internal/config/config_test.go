package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fretscha/modsec-exporter/internal/config"
)

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.toml")
	content := `
[[site]]
name       = "shop"
access_log = "/var/log/shop/access.log"
error_log  = "/var/log/shop/error.log"

[[site]]
name       = "blog"
access_log = "/var/log/blog/access.log"
error_log  = "/var/log/blog/error.log"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Sites) != 2 {
		t.Fatalf("want 2 sites, got %d", len(cfg.Sites))
	}
	if cfg.Sites[0].Name != "shop" {
		t.Errorf("sites[0].Name = %q, want shop", cfg.Sites[0].Name)
	}
	if cfg.Sites[1].AccessLog != "/var/log/blog/access.log" {
		t.Errorf("sites[1].AccessLog = %q", cfg.Sites[1].AccessLog)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_EmptyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.toml")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for empty config (no sites)")
	}
}

func TestLoad_MissingName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.toml")
	content := `
[[site]]
access_log = "/var/log/access.log"
error_log  = "/var/log/error.log"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing site name")
	}
}

func TestLoad_DuplicateName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.toml")
	content := `
[[site]]
name       = "shop"
access_log = "/var/log/shop/access.log"
error_log  = "/var/log/shop/error.log"

[[site]]
name       = "shop"
access_log = "/var/log/shop2/access.log"
error_log  = "/var/log/shop2/error.log"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate site name")
	}
}

func TestLoad_MissingAccessLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.toml")
	content := `
[[site]]
name      = "shop"
error_log = "/var/log/shop/error.log"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing access_log")
	}
}

func TestLoad_MissingErrorLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.toml")
	content := `
[[site]]
name       = "shop"
access_log = "/var/log/shop/access.log"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing error_log")
	}
}
