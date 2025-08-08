package gerrit

import (
	"encoding/json"
	"fmt"
	"gitolite-golang/internal/log"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CheckAccess checks if user has permission to access repository
func CheckAccess(gerritURL, username, repo, gerritUser, gerritToken string) (bool, error) {
	// For specific users, directly return permission granted
	log.Log(log.INFO, fmt.Sprintf("Checking access for user %s on repository %s", username, repo))
	if username == "gerrit-replication" || username == "git" || username == "gitadmin" {
		return true, nil
	}

	// First, try to check user-specific access using account API
	// This gives us more accurate permission information for the specific user
	accountAPIURL := fmt.Sprintf("%s/a/accounts/%s/capabilities", gerritURL, url.QueryEscape(username))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create request for account capabilities
	req, err := http.NewRequest("GET", accountAPIURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create account request: %v", err)
	}

	// Set basic auth
	req.SetBasicAuth(gerritUser, gerritToken)

	// Make the account request
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make account request: %v", err)
	}
	defer resp.Body.Close()

	// If account doesn't exist or we can't access it, deny access
	if resp.StatusCode == 404 {
		log.Log(log.INFO, fmt.Sprintf("User %s not found in Gerrit, denying access", username))
		return false, nil
	}

	if resp.StatusCode != 200 {
		log.Log(log.INFO, fmt.Sprintf("Account API returned status %d for user %s", resp.StatusCode, username))
		// Fallback to project access check
		return checkProjectAccess(gerritURL, username, repo, gerritUser, gerritToken, client)
	}

	// Read account response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read account response: %v", err)
	}

	// Remove Gerrit's JSON prefix
	bodyStr := string(body)
	if strings.HasPrefix(bodyStr, ")]}'\n") {
		bodyStr = bodyStr[5:]
	}

	// Parse account capabilities
	var capabilities map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &capabilities); err != nil {
		log.Log(log.INFO, fmt.Sprintf("Failed to parse account capabilities for %s: %v", username, err))
		// Fallback to project access check
		return checkProjectAccess(gerritURL, username, repo, gerritUser, gerritToken, client)
	}

	// Check if user has administrator privileges
	if _, hasAdmin := capabilities["administrateServer"]; hasAdmin {
		log.Log(log.INFO, fmt.Sprintf("User %s has administrator privileges, granting access", username))
		return true, nil
	}

	// For regular users, check project-specific access
	return checkProjectAccess(gerritURL, username, repo, gerritUser, gerritToken, client)
}

// checkProjectAccess checks project-specific access for a user
func checkProjectAccess(gerritURL, username, repo, gerritUser, gerritToken string, client *http.Client) (bool, error) {
	// Build the API URL for project access
	apiURL := fmt.Sprintf("%s/a/projects/%s/access", gerritURL, url.QueryEscape(repo))

	// Create request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create project request: %v", err)
	}

	// Set basic auth
	req.SetBasicAuth(gerritUser, gerritToken)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make project request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("project API returned status %d", resp.StatusCode)
	}

	log.Log(log.INFO, fmt.Sprintf("Project API response status code: %d", resp.StatusCode))

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read project response: %v", err)
	}

	// Check if response is empty
	if len(body) == 0 {
		log.Log(log.INFO, "Empty response from Project API")
		return false, nil
	}

	// Remove Gerrit's JSON prefix
	bodyStr := string(body)
	if strings.HasPrefix(bodyStr, ")]}'\n") {
		bodyStr = bodyStr[5:]
	}

	// Log first 100 characters of processed JSON for debugging
	if len(bodyStr) > 100 {
		log.Log(log.INFO, fmt.Sprintf("Processed JSON first 100 characters: %s", bodyStr[:100]))
	} else {
		log.Log(log.INFO, fmt.Sprintf("Processed JSON: %s", bodyStr))
	}

	// Parse JSON
	var accessInfo map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &accessInfo); err != nil {
		return false, fmt.Errorf("failed to parse project JSON: %v", err)
	}

	// Check permissions for read access
	hasAccess := checkGerritPermissions(accessInfo, username, "read")

	log.Log(log.INFO, fmt.Sprintf("User %s access check result for repository %s: %t", username, repo, hasAccess))

	return hasAccess, nil
}

// checkGerritPermissions checks permissions following Gerrit's inheritance mechanism
// Priority: BLOCK > local DENY > inherited DENY > local ALLOW > inherited ALLOW > system groups
func checkGerritPermissions(accessInfo map[string]interface{}, username, permission string) bool {
	// Step 1: Check for BLOCK rules (highest priority)
	if hasBlockRule(accessInfo, username, permission) {
		return false
	}

	// Step 2: Check local permissions
	localResult := checkLocalPermissions(accessInfo, username, permission)
	if localResult != nil {
		return *localResult
	}

	// Step 3: Check inherited permissions
	inheritedResult := checkInheritedPermissions(accessInfo, username, permission)
	if inheritedResult != nil {
		return *inheritedResult
	}

	// Step 4: Check system groups (Anonymous Users, Registered Users)
	systemResult := checkSystemGroupPermissions(accessInfo, permission)
	if systemResult != nil {
		return *systemResult
	}

	// Note: We no longer rely on is_owner or owner_of fields from the API
	// as they can be misleading when queried by admin accounts

	// Default: no access
	return false
}

// hasBlockRule checks for BLOCK rules that override all other permissions
func hasBlockRule(accessInfo map[string]interface{}, username, permission string) bool {
	// Check both local and inherited for BLOCK rules
	for _, section := range []string{"local", "inherits"} {
		if sectionData, ok := accessInfo[section].(map[string]interface{}); ok {
			if checkSectionForBlock(sectionData, username, permission) {
				return true
			}
		}
	}
	return false
}

// checkSectionForBlock checks a specific section for BLOCK rules
func checkSectionForBlock(section map[string]interface{}, username, permission string) bool {
	if refs, ok := section["refs/*"].(map[string]interface{}); ok {
		if permissions, ok := refs["permissions"].(map[string]interface{}); ok {
			if perm, ok := permissions[permission].(map[string]interface{}); ok {
				if rules, ok := perm["rules"].(map[string]interface{}); ok {
					// Check user-specific BLOCK rule
					userKey := fmt.Sprintf("user:%s", username)
					if userRule, ok := rules[userKey].(map[string]interface{}); ok {
						if action, ok := userRule["action"].(string); ok && action == "BLOCK" {
							return true
						}
					}
					// Check group BLOCK rules (would need group membership info)
					// For now, we'll focus on user-specific rules
				}
			}
		}
	}
	return false
}

// checkLocalPermissions checks local project permissions
func checkLocalPermissions(accessInfo map[string]interface{}, username, permission string) *bool {
	if local, ok := accessInfo["local"].(map[string]interface{}); ok {
		return checkPermissionInSection(local, username, permission)
	}
	return nil
}

// checkInheritedPermissions checks inherited permissions from parent projects
func checkInheritedPermissions(accessInfo map[string]interface{}, username, permission string) *bool {
	if inherits, ok := accessInfo["inherits"].(map[string]interface{}); ok {
		return checkPermissionInSection(inherits, username, permission)
	}
	return nil
}

// checkPermissionInSection checks permissions in a specific section (local or inherited)
func checkPermissionInSection(section map[string]interface{}, username, permission string) *bool {
	if refs, ok := section["refs/*"].(map[string]interface{}); ok {
		if permissions, ok := refs["permissions"].(map[string]interface{}); ok {
			if perm, ok := permissions[permission].(map[string]interface{}); ok {
				if rules, ok := perm["rules"].(map[string]interface{}); ok {
					// Check user-specific rule first
					userKey := fmt.Sprintf("user:%s", username)
					if userRule, ok := rules[userKey].(map[string]interface{}); ok {
						if action, ok := userRule["action"].(string); ok {
							switch action {
							case "DENY":
								result := false
								return &result
							case "ALLOW":
								result := true
								return &result
							}
						}
					}
					// TODO: Check group memberships if needed
					// For now, we focus on user-specific rules
				}
			}
		}
	}
	return nil
}

// checkSystemGroupPermissions checks permissions for system groups like Anonymous Users, Registered Users
func checkSystemGroupPermissions(accessInfo map[string]interface{}, permission string) *bool {
	// Check both local and inherited sections for system group permissions
	for _, section := range []string{"local", "inherits"} {
		if sectionData, ok := accessInfo[section].(map[string]interface{}); ok {
			if result := checkSystemGroupInSection(sectionData, permission); result != nil {
				return result
			}
		}
	}
	return nil
}

// checkSystemGroupInSection checks system group permissions in a specific section
func checkSystemGroupInSection(section map[string]interface{}, permission string) *bool {
	if refs, ok := section["refs/*"].(map[string]interface{}); ok {
		if permissions, ok := refs["permissions"].(map[string]interface{}); ok {
			if perm, ok := permissions[permission].(map[string]interface{}); ok {
				if rules, ok := perm["rules"].(map[string]interface{}); ok {
					// Check for Registered Users group (authenticated users)
					if regRule, ok := rules["group:Registered Users"].(map[string]interface{}); ok {
						if action, ok := regRule["action"].(string); ok {
							switch action {
							case "ALLOW":
								result := true
								return &result
							case "DENY":
								result := false
								return &result
							}
						}
					}
					// Check for Anonymous Users group
					if anonRule, ok := rules["group:Anonymous Users"].(map[string]interface{}); ok {
						if action, ok := anonRule["action"].(string); ok {
							switch action {
							case "ALLOW":
								result := true
								return &result
							case "DENY":
								result := false
								return &result
							}
						}
					}
				}
			}
		}
	}
	return nil
}
