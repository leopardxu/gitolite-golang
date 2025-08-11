package config

import (
	"fmt"
	"os"

	"gitolite-golang/internal/mirror"

	"gopkg.in/yaml.v2"
)

// Config structure definition
type Config struct {
	RepoBase        string              `yaml:"repo_base"`
	GerritURL       string              `yaml:"gerrit_url"`
	GerritUser      string              `yaml:"gerrit_user"`
	GerritRemoteURL string              `yaml:"gerrit_remote_url"` // Add Gerrit remote URL configuration
	GerritAPIToken  string              `yaml:"gerrit_api_token"`
	AuthorizedKeys  string              `yaml:"authorized_keys"`
	AccessConfig    string              `yaml:"access_config"` // Path to Gitolite-style permission configuration file
	HooksDir        string              `yaml:"hooks_dir"`     // Hook scripts directory
	Mirror          mirror.MirrorConfig `yaml:"mirror"`        // Mirror configuration
	Log             LogConfig           `yaml:"log"`
	Audit           AuditConfig         `yaml:"audit"`     // Audit configuration
	Whitelist       WhitelistConfig     `yaml:"whitelist"` // Whitelist configuration
}

// LogConfig log configuration
type LogConfig struct {
	Path     string `yaml:"path"`
	Level    string `yaml:"level"`
	Rotation string `yaml:"rotation"`
	Compress bool   `yaml:"compress"`
	MaxAge   int    `yaml:"max_age"` // Number of days to retain logs
}

// AuditConfig audit configuration
type AuditConfig struct {
	Enabled    bool   `yaml:"enabled"`     // Enable audit logging
	LogPath    string `yaml:"log_path"`    // Audit log file path
	ConsoleOut bool   `yaml:"console_out"` // Output to console
}

// WhitelistConfig whitelist configuration
type WhitelistConfig struct {
	Users []string `yaml:"users"` // List of whitelisted users who bypass permission checks
}

// LoadConfig loads configuration file and supports environment variable overrides
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %v", err)
	}

	// Load sensitive information from environment variables (if exists)
	if token := os.Getenv("GITOLITE_GERRIT_API_TOKEN"); token != "" {
		config.GerritAPIToken = token
	}

	if user := os.Getenv("GITOLITE_GERRIT_USER"); user != "" {
		config.GerritUser = user
	}

	// Validate required configuration
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	// Debug: print whitelist configuration
	fmt.Printf("DEBUG: Loaded whitelist users: %v\n", config.Whitelist.Users)

	return &config, nil
}

// validateConfig verifies if the configuration is complete and valid
func validateConfig(config *Config) error {
	if config.RepoBase == "" {
		return fmt.Errorf("missing required configuration: repo_base")
	}
	if config.GerritURL == "" {
		return fmt.Errorf("missing required configuration: gerrit_url")
	}
	if config.GerritUser == "" {
		return fmt.Errorf("missing required configuration: gerrit_user")
	}
	if config.GerritAPIToken == "" {
		return fmt.Errorf("missing required configuration: gerrit_api_token")
	}
	if config.AuthorizedKeys == "" {
		return fmt.Errorf("missing required configuration: authorized_keys")
	}
	// Set default values
	if config.AccessConfig == "" {
		config.AccessConfig = "/home/git/.gitolite/conf/gitolite.conf"
	}
	if config.HooksDir == "" {
		config.HooksDir = "/home/git/.gitolite/hooks"
	}
	return nil
}
