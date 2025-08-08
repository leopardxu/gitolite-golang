package gerrit

import (
	"encoding/json"
	"fmt"
	"gitolite-golang/internal/log"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Group represents a Gerrit group
type Group struct {
	Name string `json:"name"`
}

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
func CheckAccess(gerritURL, username, repo, gerritUser, gerritToken string) (bool, error) {
	// For specific users, directly return permission granted
	log.Log(log.INFO, fmt.Sprintf("Checking access for user %s on repository %s", username, repo))
	if username == "gerrit-replication" {
		return true, nil
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
func getUserGroups(gerritURL, gerritUser, gerritToken, username string) ([]string, error) {
	url := fmt.Sprintf("%s/a/accounts/%s/groups", gerritURL, url.QueryEscape(username))
	data, err := getGerritJSON(url, gerritUser, gerritToken)
	if err != nil {
		return nil, err
	}

	var groups []Group
	if err := json.Unmarshal([]byte(data), &groups); err != nil {
		return nil, err
	}

	groupNames := make([]string, len(groups))
	for i, group := range groups {
		groupNames[i] = group.Name
	}

	return groupNames, nil
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
	fmt.Printf("\n=== 获取继承权限 ===\n")
	fmt.Printf("项目: %s\n", projectName)
	
	var allPermissions []PermissionRule
	visited := make(map[string]bool)
	currentProject := projectName

	// Traverse the inheritance chain
	for currentProject != "" && !visited[currentProject] {
		visited[currentProject] = true
		fmt.Printf("正在处理项目: %s\n", currentProject)

		// Get project config
		projectConfig, err := getProjectConfig(gerritURL, gerritUser, gerritToken, currentProject)
		if err != nil {
			log.Log(log.INFO, fmt.Sprintf("Failed to get config for project %s: %v", currentProject, err))
			fmt.Printf("获取项目配置失败: %s, 错误: %v\n", currentProject, err)
			break
		}
		fmt.Printf("项目配置获取成功: %s\n", currentProject)

		// Parse permissions for this project
		permissions := parseReadPermissions(projectConfig, currentProject)
		fmt.Printf("解析到权限规则数量: %d\n", len(permissions))
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
	fmt.Printf("=== 开始权限评估 ===\n")
	fmt.Printf("用户组: %v\n", userGroups)
	fmt.Printf("引用: %s\n", ref)
	fmt.Printf("权限规则数量: %d\n", len(permissions))
	
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
		fmt.Printf("权限规则[%d]: 项目=%s, 动作=%s, 组=%s, 引用=%s, 优先级=%d\n", i, perm.Project, perm.Action, perm.Group, perm.Ref, perm.Priority)
	}

	// First pass: Check for BLOCK permissions - these cannot be overridden
	fmt.Printf("\n=== 检查BLOCK权限 ===\n")
	for _, perm := range permissions {
		if perm.Action == "block" && userGroupSet[perm.Group] {
			fmt.Printf("找到BLOCK规则: 组=%s, 引用=%s\n", perm.Group, perm.Ref)
			if ref == "" || refPatternMatches(perm.Ref, ref) {
				fmt.Printf("BLOCK规则匹配，拒绝访问\n")
				return false, fmt.Sprintf("Access blocked by BLOCK rule from project %s for group %s (ref: %s)", perm.Project, perm.Group, perm.Ref)
			}
		}
	}

	// Second pass: Check DENY permissions
	fmt.Printf("\n=== 检查DENY权限 ===\n")
	for _, perm := range permissions {
		if perm.Action == "deny" && userGroupSet[perm.Group] {
			fmt.Printf("找到DENY规则: 组=%s, 引用=%s\n", perm.Group, perm.Ref)
			if ref == "" || refPatternMatches(perm.Ref, ref) {
				fmt.Printf("DENY规则匹配，拒绝访问\n")
				return false, fmt.Sprintf("Access denied by rule from project %s for group %s (ref: %s)", perm.Project, perm.Group, perm.Ref)
			}
		}
	}

	// Third pass: Check READ permissions
	fmt.Printf("\n=== 检查READ权限 ===\n")
	for _, perm := range permissions {
		if perm.Action == "read" && userGroupSet[perm.Group] {
			fmt.Printf("找到READ规则: 组=%s, 引用=%s\n", perm.Group, perm.Ref)
			if ref == "" || refPatternMatches(perm.Ref, ref) {
				fmt.Printf("READ规则匹配，允许访问\n")
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

// checkProjectAccess checks user's access to project with full inheritance support
func checkProjectAccess(gerritURL, gerritUser, gerritToken, username, projectName string) (bool, error) {
	fmt.Printf("\n\n=== 开始项目访问检查 ===\n")
	fmt.Printf("用户: %s\n", username)
	fmt.Printf("项目: %s\n", projectName)
	
	userGroups, err := getUserGroups(gerritURL, gerritUser, gerritToken, username)
	if err != nil {
		log.Log(log.INFO, fmt.Sprintf("Failed to get user groups for %s: %v", username, err))
		// Use fail-close strategy for security - deny access when API fails
		log.Log(log.INFO, fmt.Sprintf("User %s denied access to project %s due to API failure (fail-close)", username, projectName))
		return false, err
	}

	log.Log(log.INFO, fmt.Sprintf("User '%s' is in groups: %v", username, userGroups))
	fmt.Printf("用户组获取成功: %v\n", userGroups)

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
