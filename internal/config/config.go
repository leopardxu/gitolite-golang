package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// Config 结构体定义
type Config struct {
	RepoBase       string    `yaml:"repo_base"`
	GerritURL      string    `yaml:"gerrit_url"`
	GerritUser     string    `yaml:"gerrit_user"`
	GerritRemoteURL string    `yaml:"gerrit_remote_url"` // 添加Gerrit远程URL配置
	GerritAPIToken string    `yaml:"gerrit_api_token"`
	AuthorizedKeys string    `yaml:"authorized_keys"`
	Log            LogConfig `yaml:"log"`
}

// LogConfig 日志配置
type LogConfig struct {
	Path     string `yaml:"path"`
	Level    string `yaml:"level"`
	Rotation string `yaml:"rotation"`
	Compress bool   `yaml:"compress"`
}

// LoadConfig 加载配置文件并支持环境变量覆盖
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 从环境变量加载敏感信息（如果存在）
	if token := os.Getenv("GITOLITE_GERRIT_API_TOKEN"); token != "" {
		config.GerritAPIToken = token
	}

	if user := os.Getenv("GITOLITE_GERRIT_USER"); user != "" {
		config.GerritUser = user
	}

	// 验证必要配置
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// 验证配置是否完整有效
func validateConfig(config *Config) error {
	if config.RepoBase == "" {
		return fmt.Errorf("缺少必要配置: repo_base")
	}
	if config.GerritURL == "" {
		return fmt.Errorf("缺少必要配置: gerrit_url")
	}
	if config.GerritUser == "" {
		return fmt.Errorf("缺少必要配置: gerrit_user")
	}
	if config.GerritAPIToken == "" {
		return fmt.Errorf("缺少必要配置: gerrit_api_token")
	}
	if config.AuthorizedKeys == "" {
		return fmt.Errorf("缺少必要配置: authorized_keys")
	}
	return nil
}
