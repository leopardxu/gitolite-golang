package access

import (
	"fmt"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"
)

// PermissionType 表示权限类型
type PermissionType string

const (
	ReadPermission    PermissionType = "R"
	WritePermission   PermissionType = "W"
	PlusPermission    PermissionType = "+"
	CreatePermission  PermissionType = "C"
	DeletePermission  PermissionType = "D"
	RewindPermission  PermissionType = "rewind"
	WildcardPermission PermissionType = "*"
)

// AccessController 访问控制器
type AccessController struct {
	Config     *AccessConfig
	ConfigPath string
}

// NewAccessController 创建新的访问控制器
func NewAccessController(configPath string) (*AccessController, error) {
	config, err := ParseConfig(configPath)
	if err != nil {
		return nil, err
	}

	return &AccessController{
		Config:     config,
		ConfigPath: configPath,
	}, nil
}

// CheckAccess 检查用户是否有权限访问仓库
func (ac *AccessController) CheckAccess(user, repo string, permType PermissionType) (bool, error) {
	// 清理仓库名称
	repo = strings.TrimSuffix(repo, ".git")

	// 首先检查是否有精确匹配的仓库配置
	if repoConfig, ok := ac.Config.Repos[repo]; ok {
		return ac.checkRepoAccess(user, repoConfig, permType)
	}

	// 如果没有精确匹配，尝试通配符匹配
	for pattern, repoConfig := range ac.Config.Repos {
		if strings.Contains(pattern, "*") {
			// 将通配符转换为正则表达式模式
			regexPattern := strings.Replace(pattern, "*", ".*", -1)
			matched, err := filepath.Match(regexPattern, repo)
			if err != nil {
				log.Log(log.WARN, fmt.Sprintf("通配符匹配错误: %v", err))
				continue
			}

			if matched {
				return ac.checkRepoAccess(user, repoConfig, permType)
			}
		}
	}

	// 如果没有找到匹配的仓库配置，默认拒绝访问
	log.Log(log.INFO, fmt.Sprintf("用户 %s 尝试访问未配置的仓库 %s", user, repo))
	return false, nil
}

// checkRepoAccess 检查用户对特定仓库的访问权限
func (ac *AccessController) checkRepoAccess(user string, repoConfig *RepoConfig, permType PermissionType) (bool, error) {
	// 检查用户直接权限
	if perms, ok := repoConfig.Permissions[user]; ok {
		if hasPermission(perms, permType) {
			return true, nil
		}
	}

	// 检查用户所属组的权限
	for groupName, members := range ac.Config.Groups {
		for _, member := range members {
			if member == user {
				// 用户属于这个组，检查组权限
				groupKey := "@" + groupName
				if perms, ok := repoConfig.Permissions[groupKey]; ok {
					if hasPermission(perms, permType) {
						return true, nil
					}
				}
			}
		}
	}

	// 检查是否有通配符用户权限
	if perms, ok := repoConfig.Permissions["@all"]; ok {
		if hasPermission(perms, permType) {
			return true, nil
		}
	}

	log.Log(log.INFO, fmt.Sprintf("用户 %s 没有仓库 %s 的 %s 权限", user, repoConfig.Name, permType))
	return false, nil
}

// hasPermission 检查权限列表中是否包含指定权限
func hasPermission(perms []string, permType PermissionType) bool {
	for _, perm := range perms {
		if strings.Contains(perm, string(permType)) || strings.Contains(perm, string(WildcardPermission)) {
			return true
		}

		// 特殊处理：W+ 权限包含 W 权限
		if permType == WritePermission && strings.Contains(perm, string(WritePermission)+string(PlusPermission)) {
			return true
		}
	}
	return false
}

// AddUserToRepo 为用户添加仓库权限
func (ac *AccessController) AddUserToRepo(user, repo string, permType PermissionType) error {
	// 清理仓库名称
	repo = strings.TrimSuffix(repo, ".git")

	// 检查仓库是否存在，不存在则创建
	if _, ok := ac.Config.Repos[repo]; !ok {
		ac.Config.Repos[repo] = &RepoConfig{
			Name:        repo,
			Permissions: make(map[string][]string),
			Groups:      make(map[string][]string),
		}
	}

	// 添加权限
	permStr := string(permType)
	ac.Config.Repos[repo].Permissions[user] = append(ac.Config.Repos[repo].Permissions[user], permStr)

	// 保存配置
	return SaveConfig(ac.Config, ac.ConfigPath)
}

// RemoveUserFromRepo 移除用户的仓库权限
func (ac *AccessController) RemoveUserFromRepo(user, repo string, permType PermissionType) error {
	// 清理仓库名称
	repo = strings.TrimSuffix(repo, ".git")

	// 检查仓库是否存在
	repoConfig, ok := ac.Config.Repos[repo]
	if !ok {
		return fmt.Errorf("仓库 %s 不存在", repo)
	}

	// 检查用户是否有权限
	perms, ok := repoConfig.Permissions[user]
	if !ok {
		return fmt.Errorf("用户 %s 没有仓库 %s 的权限", user, repo)
	}

	// 移除权限
	permStr := string(permType)
	var newPerms []string
	for _, perm := range perms {
		if !strings.Contains(perm, permStr) {
			newPerms = append(newPerms, perm)
		}
	}

	// 更新权限
	if len(newPerms) == 0 {
		delete(repoConfig.Permissions, user)
	} else {
		repoConfig.Permissions[user] = newPerms
	}

	// 保存配置
	return SaveConfig(ac.Config, ac.ConfigPath)
}

// AddGroup 添加用户组
func (ac *AccessController) AddGroup(groupName string, members []string) error {
	ac.Config.Groups[groupName] = members
	return SaveConfig(ac.Config, ac.ConfigPath)
}

// RemoveGroup 移除用户组
func (ac *AccessController) RemoveGroup(groupName string) error {
	delete(ac.Config.Groups, groupName)

	// 同时移除所有仓库中对该组的引用
	for _, repoConfig := range ac.Config.Repos {
		delete(repoConfig.Groups, groupName)
		delete(repoConfig.Permissions, "@"+groupName)
	}

	return SaveConfig(ac.Config, ac.ConfigPath)
}