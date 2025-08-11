package gerrit

import (
	"encoding/json"
	"fmt"
	"gitolite-golang/internal/config"
	"gitolite-golang/internal/log"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Group represents a Gerrit group
type Group struct {
	Name string `json:"name"`
}

// 缓存相关变量（借鉴Python版本的缓存机制）
var (
	userGroupsCache = make(map[string][]string)
	repoAccessCache = make(map[string][]PermissionRule)
	cacheMutex      sync.RWMutex
)

// ProjectInfo represents Gerrit project information
type ProjectInfo struct {
	Name   string                 `json:"name"`
	Parent string                 `json:"parent,omitempty"`
	State  string                 `json:"state,omitempty"`
	Labels map[string]interface{} `json:"labels,omitempty"`
}

// PermissionRule represents a permission rule in project config
type PermissionRule struct {
	Ref      string
	Action   string // "read", "deny", "block"
	Group    string
	Priority int    // Higher priority rules override lower priority ones
	Project  string // Which project this rule comes from (for inheritance tracking)
}

// CheckAccess checks if user has permission to access repository using Gerrit REST API
func CheckAccess(gerritURL, username, repo, gerritUser, gerritToken string, cfg *config.Config) (bool, error) {
	// For specific users, directly return permission granted
	log.Log(log.INFO, fmt.Sprintf("Checking access for user %s on repository %s", username, repo))

	// Check if user is in whitelist
	log.Log(log.INFO, fmt.Sprintf("Checking whitelist for user %s, whitelist users: %v", username, cfg.Whitelist.Users))
	for _, whitelistUser := range cfg.Whitelist.Users {
		if username == whitelistUser {
			log.Log(log.INFO, fmt.Sprintf("User %s is in whitelist, granting access", username))
			return true, nil
		}
	}

	// Check if user has access to the project (simplified check without branch-specific logic)
	hasAccess, err := checkProjectAccess(gerritURL, gerritUser, gerritToken, username, repo)
	if err != nil {
		// If Gerrit API fails, deny access directly
		log.Log(log.INFO, fmt.Sprintf("Gerrit API failed for user %s, denying access: %v", username, err))
		return false, err
	}
	return hasAccess, nil
}

// getGerritJSON calls Gerrit REST API and handles the special prefix
func getGerritJSON(url, user, token string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(user, token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Gerrit adds a ")]}'\n" prefix to JSON responses, need to remove it
	responseText := string(body)
	lines := strings.SplitN(responseText, "\n", 2)
	if len(lines) > 1 {
		return lines[1], nil
	}
	return responseText, nil
}

// getProjectInfo gets project information including parent project
func getProjectInfo(gerritURL, gerritUser, gerritToken, projectName string) (*ProjectInfo, error) {
	url := fmt.Sprintf("%s/a/projects/%s", gerritURL, url.QueryEscape(projectName))
	data, err := getGerritJSON(url, gerritUser, gerritToken)
	if err != nil {
		return nil, err
	}

	var project ProjectInfo
	if err := json.Unmarshal([]byte(data), &project); err != nil {
		return nil, err
	}

	return &project, nil
}

// getUserGroups gets all groups that the user belongs to (including nested groups)
// 优化版本：添加缓存机制和嵌套组支持（借鉴Python版本）
func getUserGroups(gerritURL, gerritUser, gerritToken, username string) ([]string, error) {
	// 检查缓存
	cacheMutex.RLock()
	if groups, exists := userGroupsCache[username]; exists {
		cacheMutex.RUnlock()
		log.Log(log.DEBUG, fmt.Sprintf("Using cached groups for user %s", username))
		return groups, nil
	}
	cacheMutex.RUnlock()

	log.Log(log.DEBUG, fmt.Sprintf("Fetching groups for user %s", username))

	groups := make(map[string]bool)
	visited := make(map[string]bool)

	// 递归获取组及其父组（嵌套组支持）
	var fetchNestedGroups func(groupName string) error
	fetchNestedGroups = func(groupName string) error {
		if visited[groupName] {
			return nil
		}
		visited[groupName] = true

		// 获取组的父组
		url := fmt.Sprintf("%s/a/groups/%s/groups/", gerritURL, url.QueryEscape(groupName))
		data, err := getGerritJSON(url, gerritUser, gerritToken)
		if err != nil {
			// 忽略获取父组失败的错误，继续处理
			log.Log(log.DEBUG, fmt.Sprintf("Failed to get parent groups for %s: %v", groupName, err))
			return nil
		}

		var parentGroups []Group
		if err := json.Unmarshal([]byte(data), &parentGroups); err != nil {
			log.Log(log.DEBUG, fmt.Sprintf("Failed to parse parent groups for %s: %v", groupName, err))
			return nil
		}

		for _, parentGroup := range parentGroups {
			groups[parentGroup.Name] = true
			if err := fetchNestedGroups(parentGroup.Name); err != nil {
				log.Log(log.DEBUG, fmt.Sprintf("Failed to fetch nested groups for %s: %v", parentGroup.Name, err))
			}
		}

		return nil
	}

	// 获取用户直接所属组
	url := fmt.Sprintf("%s/a/accounts/%s/groups", gerritURL, url.QueryEscape(username))
	data, err := getGerritJSON(url, gerritUser, gerritToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	var userGroups []Group
	if err := json.Unmarshal([]byte(data), &userGroups); err != nil {
		return nil, fmt.Errorf("failed to parse user groups: %w", err)
	}

	// 添加直接组和递归获取嵌套组
	for _, group := range userGroups {
		groups[group.Name] = true
		if err := fetchNestedGroups(group.Name); err != nil {
			log.Log(log.DEBUG, fmt.Sprintf("Failed to fetch nested groups for %s: %v", group.Name, err))
		}
	}

	// 添加内置组
	groups["Registered Users"] = true

	// 转换为切片
	result := make([]string, 0, len(groups))
	for group := range groups {
		result = append(result, group)
	}

	// 缓存结果
	cacheMutex.Lock()
	userGroupsCache[username] = result
	cacheMutex.Unlock()

	log.Log(log.DEBUG, fmt.Sprintf("Found %d groups for user %s (including nested)", len(result), username))
	return result, nil
}

// getProjectConfig gets the project.config content
func getProjectConfig(gerritURL, gerritUser, gerritToken, projectName string) (string, error) {
	// Use the files API to get the actual project.config file
	url := fmt.Sprintf("%s/a/projects/%s/branches/refs%%2Fmeta%%2Fconfig/files/project.config/content", gerritURL, url.QueryEscape(projectName))
	response, err := getGerritJSON(url, gerritUser, gerritToken)
	if err != nil {
		return "", err
	}

	// The response is a JSON string, not base64 encoded
	// Remove the outer quotes and unescape
	response = strings.Trim(response, "\"")
	// Unescape JSON string
	response = strings.ReplaceAll(response, "\\n", "\n")
	response = strings.ReplaceAll(response, "\\t", "\t")
	response = strings.ReplaceAll(response, "\\\"", "\"")
	response = strings.ReplaceAll(response, "\\u003d", "=")

	return response, nil
}

// getAccessibleProjects gets list of projects accessible to the user
func getAccessibleProjects(gerritURL, gerritUser, gerritToken, username string) ([]string, error) {
	// Use Gerrit REST API to list projects accessible to the user
	// Add query parameter to get projects visible to the user
	url := fmt.Sprintf("%s/a/projects/?format=JSON&type=ALL", gerritURL)

	// Create HTTP request with authentication
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set basic auth
	req.SetBasicAuth(gerritUser, gerritToken)
	req.Header.Set("Content-Type", "application/json")

	// Add impersonation header to get projects visible to the specific user
	if username != gerritUser {
		req.Header.Set("X-Gerrit-RunAs", username)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response := string(body)
	// Remove Gerrit's XSSI protection prefix if present
	if strings.HasPrefix(response, ")]}'\n") {
		response = response[5:]
	}

	// Parse the JSON response to extract project names
	var projects map[string]interface{}
	if err := json.Unmarshal([]byte(response), &projects); err != nil {
		return nil, fmt.Errorf("failed to parse projects response: %w", err)
	}

	var projectNames []string
	for projectName := range projects {
		projectNames = append(projectNames, projectName)
	}

	return projectNames, nil
}

// parseReadPermissions parses project.config and extracts read permission rules
func parseReadPermissions(configContent, projectName string) []PermissionRule {
	var permissions []PermissionRule
	var currentRef string

	lines := strings.Split(configContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[access \"") {
			// Extract ref from [access "refs/heads/*"]
			parts := strings.Split(line, "\"")
			if len(parts) >= 2 {
				currentRef = parts[1]
			}
		} else if strings.HasPrefix(line, "read = ") || strings.HasPrefix(line, "deny = ") {
			parts := strings.SplitN(line, " = ", 2)
			if len(parts) == 2 {
				action := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				priority := 0

				// Handle different permission formats
				if strings.HasPrefix(value, "deny ") {
					// This is a deny permission: read = deny group groupname
					groupPart := strings.TrimPrefix(value, "deny ")
					if strings.HasPrefix(groupPart, "group ") {
						groupName := strings.TrimPrefix(groupPart, "group ")
						priority = 100 // Deny has high priority
						permissions = append(permissions, PermissionRule{
							Ref:      currentRef,
							Action:   "deny",
							Group:    groupName,
							Priority: priority,
							Project:  projectName,
						})
					}
				} else if strings.HasPrefix(value, "block ") {
					// This is a block permission: read = block group groupname
					groupPart := strings.TrimPrefix(value, "block ")
					if strings.HasPrefix(groupPart, "group ") {
						groupName := strings.TrimPrefix(groupPart, "group ")
						priority = 200 // Block has highest priority
						permissions = append(permissions, PermissionRule{
							Ref:      currentRef,
							Action:   "block",
							Group:    groupName,
							Priority: priority,
							Project:  projectName,
						})
					}
				} else {
					// Regular permission format
					groupName := strings.TrimPrefix(value, "group ")
					if action == "deny" {
						priority = 100
					} else {
						priority = 50 // Regular read permission
					}
					permissions = append(permissions, PermissionRule{
						Ref:      currentRef,
						Action:   action,
						Group:    groupName,
						Priority: priority,
						Project:  projectName,
					})
				}
			}
		}
	}

	return permissions
}

// getInheritedPermissions gets permissions from project and all its parent projects
func getInheritedPermissions(gerritURL, gerritUser, gerritToken, projectName string) ([]PermissionRule, error) {
	log.Log(log.DEBUG, "=== 获取继承权限 ===")
	log.Log(log.DEBUG, fmt.Sprintf("项目: %s", projectName))

	var allPermissions []PermissionRule
	visited := make(map[string]bool)
	currentProject := projectName

	// Traverse the inheritance chain
	for currentProject != "" && !visited[currentProject] {
		visited[currentProject] = true
		log.Log(log.DEBUG, fmt.Sprintf("正在处理项目: %s", currentProject))

		// Get project config
		projectConfig, err := getProjectConfig(gerritURL, gerritUser, gerritToken, currentProject)
		if err != nil {
			log.Log(log.INFO, fmt.Sprintf("Failed to get config for project %s: %v", currentProject, err))
			log.Log(log.DEBUG, fmt.Sprintf("获取项目配置失败: %s, 错误: %v", currentProject, err))
			break
		}
		log.Log(log.DEBUG, fmt.Sprintf("项目配置获取成功: %s", currentProject))

		// Parse permissions for this project
		permissions := parseReadPermissions(projectConfig, currentProject)
		log.Log(log.DEBUG, fmt.Sprintf("解析到权限规则数量: %d", len(permissions)))
		allPermissions = append(allPermissions, permissions...)

		// Get parent project info
		projectInfo, err := getProjectInfo(gerritURL, gerritUser, gerritToken, currentProject)
		if err != nil {
			log.Log(log.INFO, fmt.Sprintf("Failed to get project info for %s: %v", currentProject, err))
			break
		}

		// Move to parent project
		currentProject = projectInfo.Parent
		if currentProject == "All-Projects" {
			// Handle All-Projects as the root
			if !visited["All-Projects"] {
				allProjectsConfig, err := getProjectConfig(gerritURL, gerritUser, gerritToken, "All-Projects")
				if err == nil {
					allProjectsPermissions := parseReadPermissions(allProjectsConfig, "All-Projects")
					allPermissions = append(allPermissions, allProjectsPermissions...)
				}
			}
			break
		}
	}

	return allPermissions, nil
}

// evaluatePermissions evaluates permissions with inheritance and priority rules
func evaluatePermissions(permissions []PermissionRule, userGroups []string, ref string) (bool, string) {
	log.Log(log.DEBUG, "=== 开始权限评估 ===")
	log.Log(log.DEBUG, fmt.Sprintf("用户组: %v", userGroups))
	log.Log(log.DEBUG, fmt.Sprintf("引用: %s", ref))
	log.Log(log.DEBUG, fmt.Sprintf("权限规则数量: %d", len(permissions)))

	userGroupSet := make(map[string]bool)
	for _, group := range userGroups {
		userGroupSet[group] = true
	}

	// Sort permissions by priority (highest first)
	sort.Slice(permissions, func(i, j int) bool {
		return permissions[i].Priority > permissions[j].Priority
	})

	// 打印所有权限规则
	for i, perm := range permissions {
		log.Log(log.DEBUG, fmt.Sprintf("权限规则[%d]: 项目=%s, 动作=%s, 组=%s, 引用=%s, 优先级=%d", i, perm.Project, perm.Action, perm.Group, perm.Ref, perm.Priority))
	}

	// First pass: Check for BLOCK permissions - these cannot be overridden
	log.Log(log.DEBUG, "=== 检查BLOCK权限 ===")
	for _, perm := range permissions {
		if perm.Action == "block" && userGroupSet[perm.Group] {
			log.Log(log.DEBUG, fmt.Sprintf("找到BLOCK规则: 组=%s, 引用=%s", perm.Group, perm.Ref))
			if ref == "" || refPatternMatches(perm.Ref, ref) {
				log.Log(log.DEBUG, "BLOCK规则匹配，拒绝访问")
				return false, fmt.Sprintf("Access blocked by BLOCK rule from project %s for group %s (ref: %s)", perm.Project, perm.Group, perm.Ref)
			}
		}
	}

	// Second pass: Check DENY permissions
	log.Log(log.DEBUG, "=== 检查DENY权限 ===")
	for _, perm := range permissions {
		if perm.Action == "deny" && userGroupSet[perm.Group] {
			log.Log(log.DEBUG, fmt.Sprintf("找到DENY规则: 组=%s, 引用=%s", perm.Group, perm.Ref))
			if ref == "" || refPatternMatches(perm.Ref, ref) {
				log.Log(log.DEBUG, "DENY规则匹配，拒绝访问")
				return false, fmt.Sprintf("Access denied by rule from project %s for group %s (ref: %s)", perm.Project, perm.Group, perm.Ref)
			}
		}
	}

	// Third pass: Check READ permissions
	log.Log(log.DEBUG, "=== 检查READ权限 ===")
	for _, perm := range permissions {
		if perm.Action == "read" && userGroupSet[perm.Group] {
			log.Log(log.DEBUG, fmt.Sprintf("找到READ规则: 组=%s, 引用=%s", perm.Group, perm.Ref))
			if ref == "" || refPatternMatches(perm.Ref, ref) {
				log.Log(log.DEBUG, "READ规则匹配，允许访问")
				return true, fmt.Sprintf("Access granted by rule from project %s for group %s (ref: %s)", perm.Project, perm.Group, perm.Ref)
			}
		}
	}

	// No matching permissions found
	return false, "No matching permissions found"
}

// refPatternMatches checks if ref pattern matches specific ref
func refPatternMatches(pattern, ref string) bool {
	// Simple implementation, handle * wildcard
	// More complex implementation needs to handle ** and regular expressions
	regexPattern := strings.ReplaceAll(pattern, "*", "[^/]*")
	if strings.Contains(pattern, "**") {
		regexPattern = strings.ReplaceAll(pattern, "**", ".*")
	}

	matched, err := regexp.MatchString("^"+regexPattern+"$", ref)
	if err != nil {
		return false
	}
	return matched
}

// ClearCache 清空所有缓存（借鉴Python版本的缓存管理）
func ClearCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	userGroupsCache = make(map[string][]string)
	repoAccessCache = make(map[string][]PermissionRule)
	log.Log(log.DEBUG, "All caches cleared")
}

// ClearUserCache 清空特定用户的缓存
func ClearUserCache(username string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	delete(userGroupsCache, username)
	log.Log(log.DEBUG, fmt.Sprintf("Cache cleared for user %s", username))
}

// ClearRepoCache 清空特定仓库的缓存
func ClearRepoCache(repoName string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	delete(repoAccessCache, repoName)
	log.Log(log.DEBUG, fmt.Sprintf("Cache cleared for repo %s", repoName))
}

// GetCacheStats 获取缓存统计信息
func GetCacheStats() (int, int) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	return len(userGroupsCache), len(repoAccessCache)
}

// checkProjectAccess checks user's access to project with full inheritance support
func checkProjectAccess(gerritURL, gerritUser, gerritToken, username, projectName string) (bool, error) {
	log.Log(log.DEBUG, "=== 开始项目访问检查 ===")
	log.Log(log.DEBUG, fmt.Sprintf("用户: %s", username))
	log.Log(log.DEBUG, fmt.Sprintf("项目: %s", projectName))

	userGroups, err := getUserGroups(gerritURL, gerritUser, gerritToken, username)
	if err != nil {
		log.Log(log.INFO, fmt.Sprintf("Failed to get user groups for %s: %v", username, err))
		// Use fail-close strategy for security - deny access when API fails
		log.Log(log.INFO, fmt.Sprintf("User %s denied access to project %s due to API failure (fail-close)", username, projectName))
		return false, err
	}

	log.Log(log.INFO, fmt.Sprintf("User '%s' is in groups: %v", username, userGroups))
	log.Log(log.DEBUG, fmt.Sprintf("用户组获取成功: %v", userGroups))

	// Get inherited permissions from project and all parent projects
	permissions, err := getInheritedPermissions(gerritURL, gerritUser, gerritToken, projectName)
	if err != nil {
		log.Log(log.INFO, fmt.Sprintf("Failed to get inherited permissions for project %s: %v", projectName, err))
		// Use fail-close strategy for security
		log.Log(log.INFO, fmt.Sprintf("User %s denied access to project %s due to permission retrieval failure (fail-close)", username, projectName))
		return false, err
	}

	log.Log(log.INFO, fmt.Sprintf("Found %d permission rules for project %s (including inherited)", len(permissions), projectName))

	// Evaluate permissions with proper priority and inheritance handling
	// Skip ref pattern matching for general access check
	hasAccess, reason := evaluatePermissions(permissions, userGroups, "")

	if hasAccess {
		log.Log(log.INFO, fmt.Sprintf("User %s granted access to project %s: %s", username, projectName, reason))
	} else {
		log.Log(log.INFO, fmt.Sprintf("User %s denied access to project %s: %s", username, projectName, reason))
	}

	return hasAccess, nil
}
