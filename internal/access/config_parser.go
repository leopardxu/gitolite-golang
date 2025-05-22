package access

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gitolite-golang/internal/log"
)

// RepoConfig 表示一个仓库的配置信息
type RepoConfig struct {
	Name        string
	Permissions map[string][]string // 用户/组 -> 权限列表
	Groups      map[string][]string // 组名 -> 用户列表
}

// AccessConfig 表示整个访问控制配置
type AccessConfig struct {
	Repos  map[string]*RepoConfig // 仓库名 -> 仓库配置
	Groups map[string][]string    // 全局组定义
}

// ParseConfig 解析Gitolite风格的配置文件
func ParseConfig(configPath string) (*AccessConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("打开配置文件失败: %w", err)
	}
	defer file.Close()

	config := &AccessConfig{
		Repos:  make(map[string]*RepoConfig),
		Groups: make(map[string][]string),
	}

	scanner := bufio.NewScanner(file)
	var currentRepo *RepoConfig

	// 正则表达式匹配仓库定义行
	repoRegex := regexp.MustCompile(`^repo\s+(.+)$`)
	// 正则表达式匹配权限定义行
	permRegex := regexp.MustCompile(`^\s*([-RW+CD]+)\s*=\s*(.+)$`)
	// 正则表达式匹配组定义行
	groupRegex := regexp.MustCompile(`^@([\w-]+)\s*=\s*(.+)$`)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 匹配组定义
		if matches := groupRegex.FindStringSubmatch(line); len(matches) > 0 {
			groupName := matches[1]
			members := strings.Fields(matches[2])
			config.Groups[groupName] = members
			continue
		}

		// 匹配仓库定义
		if matches := repoRegex.FindStringSubmatch(line); len(matches) > 0 {
			repoNames := strings.Fields(matches[1])
			for _, name := range repoNames {
				// 处理通配符
				if strings.Contains(name, "*") {
					// 在实际实现中，这里需要展开通配符匹配的所有仓库
					// 简化版本中，我们直接使用通配符作为键
					config.Repos[name] = &RepoConfig{
						Name:        name,
						Permissions: make(map[string][]string),
						Groups:      make(map[string][]string),
					}
				} else {
					config.Repos[name] = &RepoConfig{
						Name:        name,
						Permissions: make(map[string][]string),
						Groups:      make(map[string][]string),
					}
				}
			}
			currentRepo = config.Repos[repoNames[0]]
			continue
		}

		// 匹配权限定义
		if currentRepo != nil {
			if matches := permRegex.FindStringSubmatch(line); len(matches) > 0 {
				perm := matches[1]
				users := strings.Fields(matches[2])
				for _, user := range users {
					// 处理组引用
					if strings.HasPrefix(user, "@") {
						groupName := user[1:]
						currentRepo.Groups[groupName] = config.Groups[groupName]
					}
					currentRepo.Permissions[user] = append(currentRepo.Permissions[user], perm)
				}
				continue
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	log.Log(log.INFO, fmt.Sprintf("成功解析访问控制配置，共 %d 个仓库定义", len(config.Repos)))
	return config, nil
}

// SaveConfig 保存配置到文件
func SaveConfig(config *AccessConfig, configPath string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("创建配置文件失败: %w", err)
	}
	defer file.Close()

	// 写入全局组定义
	for groupName, members := range config.Groups {
		_, err := fmt.Fprintf(file, "@%s = %s\n", groupName, strings.Join(members, " "))
		if err != nil {
			return fmt.Errorf("写入组定义失败: %w", err)
		}
	}

	// 写入空行分隔
	_, err = fmt.Fprintln(file, "")
	if err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	// 写入仓库定义和权限
	for _, repo := range config.Repos {
		_, err := fmt.Fprintf(file, "repo %s\n", repo.Name)
		if err != nil {
			return fmt.Errorf("写入仓库定义失败: %w", err)
		}

		// 写入权限
		for user, perms := range repo.Permissions {
			for _, perm := range perms {
				_, err := fmt.Fprintf(file, "    %s = %s\n", perm, user)
				if err != nil {
					return fmt.Errorf("写入权限定义失败: %w", err)
				}
			}
		}

		// 写入空行分隔
		_, err = fmt.Fprintln(file, "")
		if err != nil {
			return fmt.Errorf("写入配置文件失败: %w", err)
		}
	}

	log.Log(log.INFO, fmt.Sprintf("成功保存访问控制配置到 %s", configPath))
	return nil
}