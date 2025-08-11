package gerrit

import (
	"encoding/json"
	"fmt"
	"gitolite-golang/internal/log"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GerritPermissionChecker 优化版本的Gerrit权限检查器
// 借鉴Python版本的设计思路，增加缓存和更好的API使用
type GerritPermissionChecker struct {
	gerritURL  string
	adminToken string
	client     *http.Client

	// 缓存机制
	userGroupsCache map[string][]string
	repoAccessCache map[string][]AccessRule
	cacheMutex      sync.RWMutex
}

// AccessRule 访问规则结构
type AccessRule struct {
	Ref      string   `json:"ref"`
	Action   string   `json:"action"` // ALLOW, DENY, BLOCK
	Groups   []string `json:"groups"`
	Users    []string `json:"users"`
	Priority int      `json:"priority"`
	Project  string   `json:"project"`
}

// AccessResponse Gerrit access API响应结构
type AccessResponse struct {
	Local        map[string]RefPermissions `json:"local"`
	InheritsFrom *ProjectRef               `json:"inherits_from"`
}

// RefPermissions 引用权限结构
type RefPermissions struct {
	Ref         string                `json:"ref"`
	Permissions map[string]Permission `json:"permissions"`
}

// Permission 权限结构
type Permission struct {
	Rules []PermissionRuleDetail `json:"rules"`
}

// PermissionRuleDetail 权限规则详情
type PermissionRuleDetail struct {
	Action string `json:"action"`
	Group  Group  `json:"group"`
}

// ProjectRef 项目引用
type ProjectRef struct {
	Name string `json:"name"`
}

// GroupDetail 组详情
type GroupDetail struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// NewGerritPermissionChecker 创建新的权限检查器实例
func NewGerritPermissionChecker(gerritURL, adminToken string) *GerritPermissionChecker {
	return &GerritPermissionChecker{
		gerritURL:       strings.TrimSuffix(gerritURL, "/"),
		adminToken:      adminToken,
		client:          &http.Client{Timeout: 30 * time.Second},
		userGroupsCache: make(map[string][]string),
		repoAccessCache: make(map[string][]AccessRule),
	}
}

// GetUserGroups 获取用户所属的所有组（包括嵌套组）
func (g *GerritPermissionChecker) GetUserGroups(username string) ([]string, error) {
	// 检查缓存
	g.cacheMutex.RLock()
	if groups, exists := g.userGroupsCache[username]; exists {
		g.cacheMutex.RUnlock()
		return groups, nil
	}
	g.cacheMutex.RUnlock()

	groups := make(map[string]bool)
	visited := make(map[string]bool)

	// 递归获取组及其父组
	var fetchGroups func(groupID string) error
	fetchGroups = func(groupID string) error {
		if visited[groupID] {
			return nil
		}
		visited[groupID] = true

		// 获取组的父组
		url := fmt.Sprintf("%s/a/groups/%s/groups/", g.gerritURL, url.QueryEscape(groupID))
		data, err := g.getGerritJSON(url)
		if err != nil {
			// 忽略获取父组失败的错误，继续处理
			log.Log(log.DEBUG, fmt.Sprintf("Failed to get parent groups for %s: %v", groupID, err))
			return nil
		}

		var parentGroups []GroupDetail
		if err := json.Unmarshal([]byte(data), &parentGroups); err != nil {
			return err
		}

		for _, parentGroup := range parentGroups {
			groups[parentGroup.Name] = true
			if err := fetchGroups(parentGroup.ID); err != nil {
				log.Log(log.DEBUG, fmt.Sprintf("Failed to fetch nested groups for %s: %v", parentGroup.ID, err))
			}
		}

		return nil
	}

	// 获取用户直接所属组
	url := fmt.Sprintf("%s/a/accounts/%s/groups/", g.gerritURL, url.QueryEscape(username))
	data, err := g.getGerritJSON(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	var userGroups []GroupDetail
	if err := json.Unmarshal([]byte(data), &userGroups); err != nil {
		return nil, fmt.Errorf("failed to parse user groups: %w", err)
	}

	for _, group := range userGroups {
		groups[group.Name] = true
		if err := fetchGroups(group.ID); err != nil {
			log.Log(log.DEBUG, fmt.Sprintf("Failed to fetch nested groups for %s: %v", group.ID, err))
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
	g.cacheMutex.Lock()
	g.userGroupsCache[username] = result
	g.cacheMutex.Unlock()

	return result, nil
}

// GetRepoAccessRules 获取仓库的访问控制规则（包括继承规则）
func (g *GerritPermissionChecker) GetRepoAccessRules(repoName string) ([]AccessRule, error) {
	// 检查缓存
	g.cacheMutex.RLock()
	if rules, exists := g.repoAccessCache[repoName]; exists {
		g.cacheMutex.RUnlock()
		return rules, nil
	}
	g.cacheMutex.RUnlock()

	url := fmt.Sprintf("%s/a/projects/%s/access/", g.gerritURL, url.QueryEscape(repoName))
	data, err := g.getGerritJSON(url)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, fmt.Errorf("repository %s not found", repoName)
		}
		return nil, fmt.Errorf("failed to get access rules: %w", err)
	}

	var accessResp AccessResponse
	if err := json.Unmarshal([]byte(data), &accessResp); err != nil {
		return nil, fmt.Errorf("failed to parse access response: %w", err)
	}

	var rules []AccessRule

	// 提取本地规则
	for refPattern, refPerms := range accessResp.Local {
		if readPerm, exists := refPerms.Permissions["read"]; exists {
			for _, rule := range readPerm.Rules {
				rules = append(rules, AccessRule{
					Ref:      refPattern,
					Action:   rule.Action,
					Groups:   []string{rule.Group.Name},
					Priority: g.getActionPriority(rule.Action),
					Project:  repoName,
				})
			}
		}
	}

	// 提取继承规则
	if accessResp.InheritsFrom != nil {
		parentRules, err := g.GetRepoAccessRules(accessResp.InheritsFrom.Name)
		if err != nil {
			log.Log(log.DEBUG, fmt.Sprintf("Failed to get parent rules for %s: %v", accessResp.InheritsFrom.Name, err))
		} else {
			rules = append(rules, parentRules...)
		}
	}

	// 缓存结果
	g.cacheMutex.Lock()
	g.repoAccessCache[repoName] = rules
	g.cacheMutex.Unlock()

	return rules, nil
}

// HasReadPermission 判断用户是否有仓库的READ权限
func (g *GerritPermissionChecker) HasReadPermission(username, repoName string) (bool, error) {
	// 获取用户所属组
	userGroups, err := g.GetUserGroups(username)
	if err != nil {
		return false, fmt.Errorf("failed to get user groups: %w", err)
	}

	userGroupSet := make(map[string]bool)
	for _, group := range userGroups {
		userGroupSet[group] = true
	}

	// 获取仓库访问规则
	rules, err := g.GetRepoAccessRules(repoName)
	if err != nil {
		return false, fmt.Errorf("failed to get repo access rules: %w", err)
	}

	// 按规则优先级排序（高优先级在前）
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Priority < rules[j].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	// 按规则顺序检查
	for _, rule := range rules {
		// 检查用户直接匹配
		for _, user := range rule.Users {
			if user == username {
				switch rule.Action {
				case "BLOCK", "DENY":
					return false, nil
				case "ALLOW":
					return true, nil
				}
			}
		}

		// 检查组匹配
		for _, groupName := range rule.Groups {
			if userGroupSet[groupName] {
				switch rule.Action {
				case "BLOCK", "DENY":
					return false, nil
				case "ALLOW":
					return true, nil
				}
			}
		}
	}

	// 没有匹配规则，默认拒绝
	return false, nil
}

// getGerritJSON 调用Gerrit REST API并处理特殊前缀
func (g *GerritPermissionChecker) getGerritJSON(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.adminToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
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

	// 处理Gerrit的)]}'前缀
	content := string(body)
	if strings.HasPrefix(content, ")]}'") {
		content = content[4:]
	}

	return content, nil
}

// getActionPriority 获取动作的优先级
func (g *GerritPermissionChecker) getActionPriority(action string) int {
	switch action {
	case "BLOCK":
		return 200
	case "DENY":
		return 100
	case "ALLOW":
		return 50
	default:
		return 0
	}
}

// ClearCache 清空缓存
func (g *GerritPermissionChecker) ClearCache() {
	g.cacheMutex.Lock()
	defer g.cacheMutex.Unlock()

	g.userGroupsCache = make(map[string][]string)
	g.repoAccessCache = make(map[string][]AccessRule)
}

// ClearUserCache 清空特定用户的缓存
func (g *GerritPermissionChecker) ClearUserCache(username string) {
	g.cacheMutex.Lock()
	defer g.cacheMutex.Unlock()

	delete(g.userGroupsCache, username)
}

// ClearRepoCache 清空特定仓库的缓存
func (g *GerritPermissionChecker) ClearRepoCache(repoName string) {
	g.cacheMutex.Lock()
	defer g.cacheMutex.Unlock()

	delete(g.repoAccessCache, repoName)
}
