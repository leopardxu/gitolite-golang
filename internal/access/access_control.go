package access

import (
	"fmt"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"
)

// PermissionType represents permission type
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

// AccessController access controller
type AccessController struct {
	Config     *AccessConfig
	ConfigPath string
}

// NewAccessController creates a new access controller
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

// CheckAccess checks if a user has permission to access a repository
func (ac *AccessController) CheckAccess(user, repo string, permType PermissionType) (bool, error) {
	// Clean repository name
	repo = strings.TrimSuffix(repo, ".git")

	// First check if there is an exact match for the repository configuration
	if repoConfig, ok := ac.Config.Repos[repo]; ok {
		return ac.checkRepoAccess(user, repoConfig, permType)
	}

	// If no exact match, try wildcard matching
	for pattern, repoConfig := range ac.Config.Repos {
		if strings.Contains(pattern, "*") {
			// Convert wildcard to regex pattern
			regexPattern := strings.Replace(pattern, "*", ".*", -1)
			matched, err := filepath.Match(regexPattern, repo)
			if err != nil {
				log.Log(log.WARN, fmt.Sprintf("Wildcard matching error: %v", err))
				continue
			}

			if matched {
				return ac.checkRepoAccess(user, repoConfig, permType)
			}
		}
	}

	// If no matching repository configuration is found, deny access by default
	log.Log(log.INFO, fmt.Sprintf("User %s attempted to access unconfigured repository %s", user, repo))
	return false, nil
}

// checkRepoAccess checks a user's access permission for a specific repository
func (ac *AccessController) checkRepoAccess(user string, repoConfig *RepoConfig, permType PermissionType) (bool, error) {
	// Check user direct permissions
	if perms, ok := repoConfig.Permissions[user]; ok {
		if hasPermission(perms, permType) {
			return true, nil
		}
	}

	// Check permissions of groups the user belongs to
	for groupName, members := range ac.Config.Groups {
		for _, member := range members {
			if member == user {
				// User belongs to this group, check group permissions
				groupKey := "@" + groupName
				if perms, ok := repoConfig.Permissions[groupKey]; ok {
					if hasPermission(perms, permType) {
						return true, nil
					}
				}
			}
		}
	}

	// Check if there are wildcard user permissions
	if perms, ok := repoConfig.Permissions["@all"]; ok {
		if hasPermission(perms, permType) {
			return true, nil
		}
	}

	log.Log(log.INFO, fmt.Sprintf("User %s does not have %s permission for repository %s", user, permType, repoConfig.Name))
	return false, nil
}

// hasPermission checks if the permission list contains the specified permission
func hasPermission(perms []string, permType PermissionType) bool {
	for _, perm := range perms {
		if strings.Contains(perm, string(permType)) || strings.Contains(perm, string(WildcardPermission)) {
			return true
		}

		// Special handling: W+ permission includes W permission
		if permType == WritePermission && strings.Contains(perm, string(WritePermission)+string(PlusPermission)) {
			return true
		}
	}
	return false
}

// AddUserToRepo adds repository permission for a user
func (ac *AccessController) AddUserToRepo(user, repo string, permType PermissionType) error {
	// Clean repository name
	repo = strings.TrimSuffix(repo, ".git")

	// Check if repository exists, create if not
	if _, ok := ac.Config.Repos[repo]; !ok {
		ac.Config.Repos[repo] = &RepoConfig{
			Name:        repo,
			Permissions: make(map[string][]string),
			Groups:      make(map[string][]string),
		}
	}

	// Add permission
	permStr := string(permType)
	ac.Config.Repos[repo].Permissions[user] = append(ac.Config.Repos[repo].Permissions[user], permStr)

	// Save configuration
	return SaveConfig(ac.Config, ac.ConfigPath)
}

// RemoveUserFromRepo removes repository permission for a user
func (ac *AccessController) RemoveUserFromRepo(user, repo string, permType PermissionType) error {
	// Clean repository name
	repo = strings.TrimSuffix(repo, ".git")

	// Check if repository exists
	repoConfig, ok := ac.Config.Repos[repo]
	if !ok {
		return fmt.Errorf("repository %s does not exist", repo)
	}

	// Check if user has permission
	perms, ok := repoConfig.Permissions[user]
	if !ok {
		return fmt.Errorf("user %s does not have permission for repository %s", user, repo)
	}

	// Remove permission
	permStr := string(permType)
	var newPerms []string
	for _, perm := range perms {
		if !strings.Contains(perm, permStr) {
			newPerms = append(newPerms, perm)
		}
	}

	// Update permissions
	if len(newPerms) == 0 {
		delete(repoConfig.Permissions, user)
	} else {
		repoConfig.Permissions[user] = newPerms
	}

	// Save configuration
	return SaveConfig(ac.Config, ac.ConfigPath)
}

// AddGroup adds a user group
func (ac *AccessController) AddGroup(groupName string, members []string) error {
	ac.Config.Groups[groupName] = members
	return SaveConfig(ac.Config, ac.ConfigPath)
}

// RemoveGroup removes a user group
func (ac *AccessController) RemoveGroup(groupName string) error {
	delete(ac.Config.Groups, groupName)

	// Also remove references to this group from all repositories
	for _, repoConfig := range ac.Config.Repos {
		delete(repoConfig.Groups, groupName)
		delete(repoConfig.Permissions, "@"+groupName)
	}

	return SaveConfig(ac.Config, ac.ConfigPath)
}