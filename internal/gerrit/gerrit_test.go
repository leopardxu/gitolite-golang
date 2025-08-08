package gerrit

import (
	"encoding/json"
	"fmt"
	"gitolite-golang/internal/log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mock Gerrit server for testing
func createMockGerritServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Log(log.INFO, fmt.Sprintf("Mock server received request: %s %s", r.Method, r.URL.Path))
		
		// Handle different API endpoints
		switch {
		case strings.Contains(r.URL.Path, "/accounts/testuser/groups"):
			// Return user groups
			groups := []Group{
				{Name: "Registered Users"},
				{Name: "Developers"},
			}
			response, _ := json.Marshal(groups)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(response)))
			
		case strings.Contains(r.URL.Path, "/accounts/blockeduser/groups"):
			// Return blocked user groups
			groups := []Group{
				{Name: "Registered Users"},
				{Name: "Blocked Group"},
			}
			response, _ := json.Marshal(groups)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(response)))
			
		case strings.Contains(r.URL.Path, "/projects/test-project") && !strings.Contains(r.URL.Path, "branches"):
			// Return project info
			project := ProjectInfo{
				Name:   "test-project",
				Parent: "parent-project",
				State:  "ACTIVE",
			}
			response, _ := json.Marshal(project)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(response)))
			
		case strings.Contains(r.URL.Path, "/projects/parent-project") && !strings.Contains(r.URL.Path, "branches"):
			// Return parent project info
			project := ProjectInfo{
				Name:   "parent-project",
				Parent: "All-Projects",
				State:  "ACTIVE",
			}
			response, _ := json.Marshal(project)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(response)))
			
		case strings.Contains(r.URL.Path, "/projects/All-Projects") && !strings.Contains(r.URL.Path, "branches"):
			// Return All-Projects info
			project := ProjectInfo{
				Name:  "All-Projects",
				State: "ACTIVE",
			}
			response, _ := json.Marshal(project)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(response)))
			
		case strings.Contains(r.URL.Path, "/projects/test-project/branches/refs%2Fmeta%2Fconfig/files/project.config/content") || strings.Contains(r.URL.Path, "/projects/test-project/branches/refs/meta/config/files/project.config/content"):
			// Return test project config
			config := `[access "refs/heads/*"]
	read = group Developers
	read = deny group Blocked Group
[access "refs/tags/*"]
	read = group Registered Users`
			configJSON, _ := json.Marshal(config)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(configJSON)))
			
		case strings.Contains(r.URL.Path, "/projects/parent-project/branches/refs%2Fmeta%2Fconfig/files/project.config/content") || strings.Contains(r.URL.Path, "/projects/parent-project/branches/refs/meta/config/files/project.config/content"):
			// Return parent project config
			config := `[access "refs/heads/*"]
	read = group Registered Users
[access "refs/for/refs/heads/*"]
	push = group Developers`
			configJSON, _ := json.Marshal(config)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(configJSON)))
			
		case strings.Contains(r.URL.Path, "/projects/All-Projects/branches/refs%2Fmeta%2Fconfig/files/project.config/content") || strings.Contains(r.URL.Path, "/projects/All-Projects/branches/refs/meta/config/files/project.config/content"):
			// Return All-Projects config with BLOCK rule
			config := `[access "refs/heads/*"]
	read = group Anonymous Users
	read = block group Blocked Group
[access "refs/meta/config"]
	read = group Administrators`
			configJSON, _ := json.Marshal(config)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(")]}'\n" + string(configJSON)))
			
		default:
			log.Log(log.INFO, fmt.Sprintf("Mock server: unhandled request %s", r.URL.Path))
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestCheckAccess(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestCheckAccess ===")
	
	mockServer := createMockGerritServer()
	defer mockServer.Close()
	
	tests := []struct {
		name     string
		username string
		repo     string
		expected bool
	}{
		{
			name:     "gerrit-replication user should have access",
			username: "gerrit-replication",
			repo:     "any-repo",
			expected: true,
		},
		{
			name:     "regular user with access",
			username: "testuser",
			repo:     "test-project",
			expected: true,
		},
		{
			name:     "blocked user should be denied",
			username: "blockeduser",
			repo:     "test-project",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Log(log.INFO, fmt.Sprintf("Running test: %s", tt.name))
			
			result, err := CheckAccess(mockServer.URL, tt.username, tt.repo, "admin", "token")
			
			log.Log(log.INFO, fmt.Sprintf("Test result for %s: access=%v, error=%v", tt.name, result, err))
			
			if result != tt.expected {
				t.Errorf("CheckAccess() = %v, want %v", result, tt.expected)
			}
		})
	}
	
	log.Log(log.INFO, "=== Finished TestCheckAccess ===")
}

func TestGetUserGroups(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestGetUserGroups ===")
	
	mockServer := createMockGerritServer()
	defer mockServer.Close()
	
	tests := []struct {
		name     string
		username string
		expected []string
	}{
		{
			name:     "testuser groups",
			username: "testuser",
			expected: []string{"Registered Users", "Developers"},
		},
		{
			name:     "blockeduser groups",
			username: "blockeduser",
			expected: []string{"Registered Users", "Blocked Group"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Log(log.INFO, fmt.Sprintf("Testing getUserGroups for user: %s", tt.username))
			
			groups, err := getUserGroups(mockServer.URL, "admin", "token", tt.username)
			
			log.Log(log.INFO, fmt.Sprintf("User %s groups: %v, error: %v", tt.username, groups, err))
			
			if err != nil {
				t.Errorf("getUserGroups() error = %v", err)
				return
			}
			
			if len(groups) != len(tt.expected) {
				t.Errorf("getUserGroups() = %v, want %v", groups, tt.expected)
				return
			}
			
			for i, group := range groups {
				if group != tt.expected[i] {
					t.Errorf("getUserGroups()[%d] = %v, want %v", i, group, tt.expected[i])
				}
			}
		})
	}
	
	log.Log(log.INFO, "=== Finished TestGetUserGroups ===")
}

func TestGetProjectInfo(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestGetProjectInfo ===")
	
	mockServer := createMockGerritServer()
	defer mockServer.Close()
	
	tests := []struct {
		name        string
		projectName string
		expected    *ProjectInfo
	}{
		{
			name:        "test project info",
			projectName: "test-project",
			expected: &ProjectInfo{
				Name:   "test-project",
				Parent: "parent-project",
				State:  "ACTIVE",
			},
		},
		{
			name:        "parent project info",
			projectName: "parent-project",
			expected: &ProjectInfo{
				Name:   "parent-project",
				Parent: "All-Projects",
				State:  "ACTIVE",
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Log(log.INFO, fmt.Sprintf("Testing getProjectInfo for project: %s", tt.projectName))
			
			project, err := getProjectInfo(mockServer.URL, "admin", "token", tt.projectName)
			
			log.Log(log.INFO, fmt.Sprintf("Project %s info: %+v, error: %v", tt.projectName, project, err))
			
			if err != nil {
				t.Errorf("getProjectInfo() error = %v", err)
				return
			}
			
			if project.Name != tt.expected.Name {
				t.Errorf("getProjectInfo().Name = %v, want %v", project.Name, tt.expected.Name)
			}
			
			if project.Parent != tt.expected.Parent {
				t.Errorf("getProjectInfo().Parent = %v, want %v", project.Parent, tt.expected.Parent)
			}
		})
	}
	
	log.Log(log.INFO, "=== Finished TestGetProjectInfo ===")
}

func TestParseReadPermissions(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestParseReadPermissions ===")
	
	tests := []struct {
		name           string
		configContent  string
		projectName    string
		expectedCount  int
		expectedRules  []PermissionRule
	}{
		{
			name: "basic permissions",
			configContent: `[access "refs/heads/*"]
	read = group Developers
	read = deny group Blocked Group
[access "refs/tags/*"]
	read = group Registered Users`,
			projectName: "test-project",
			expectedCount: 3,
			expectedRules: []PermissionRule{
				{Ref: "refs/heads/*", Action: "read", Group: "Developers", Priority: 50, Project: "test-project"},
				{Ref: "refs/heads/*", Action: "deny", Group: "Blocked Group", Priority: 100, Project: "test-project"},
				{Ref: "refs/tags/*", Action: "read", Group: "Registered Users", Priority: 50, Project: "test-project"},
			},
		},
		{
			name: "block permissions",
			configContent: `[access "refs/heads/*"]
	read = block group Blocked Group
	read = group Anonymous Users`,
			projectName: "All-Projects",
			expectedCount: 2,
			expectedRules: []PermissionRule{
				{Ref: "refs/heads/*", Action: "block", Group: "Blocked Group", Priority: 200, Project: "All-Projects"},
				{Ref: "refs/heads/*", Action: "read", Group: "Anonymous Users", Priority: 50, Project: "All-Projects"},
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Log(log.INFO, fmt.Sprintf("Testing parseReadPermissions for project: %s", tt.projectName))
			log.Log(log.INFO, fmt.Sprintf("Config content:\n%s", tt.configContent))
			
			permissions := parseReadPermissions(tt.configContent, tt.projectName)
			
			log.Log(log.INFO, fmt.Sprintf("Parsed %d permissions for project %s", len(permissions), tt.projectName))
			for i, perm := range permissions {
				log.Log(log.INFO, fmt.Sprintf("Permission[%d]: Ref=%s, Action=%s, Group=%s, Priority=%d, Project=%s", 
					i, perm.Ref, perm.Action, perm.Group, perm.Priority, perm.Project))
			}
			
			if len(permissions) != tt.expectedCount {
				t.Errorf("parseReadPermissions() returned %d permissions, want %d", len(permissions), tt.expectedCount)
				return
			}
			
			for i, expected := range tt.expectedRules {
				if i >= len(permissions) {
					t.Errorf("Missing permission rule at index %d", i)
					continue
				}
				
				actual := permissions[i]
				if actual.Ref != expected.Ref || actual.Action != expected.Action || 
				   actual.Group != expected.Group || actual.Priority != expected.Priority ||
				   actual.Project != expected.Project {
					t.Errorf("Permission[%d] = %+v, want %+v", i, actual, expected)
				}
			}
		})
	}
	
	log.Log(log.INFO, "=== Finished TestParseReadPermissions ===")
}

func TestEvaluatePermissions(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestEvaluatePermissions ===")
	
	tests := []struct {
		name        string
		permissions []PermissionRule
		userGroups  []string
		ref         string
		expected    bool
		reason      string
	}{
		{
			name: "block permission denies access",
			permissions: []PermissionRule{
				{Ref: "refs/heads/*", Action: "read", Group: "Developers", Priority: 50, Project: "test"},
				{Ref: "refs/heads/*", Action: "block", Group: "Blocked Group", Priority: 200, Project: "All-Projects"},
			},
			userGroups: []string{"Developers", "Blocked Group"},
			ref:        "refs/heads/master",
			expected:   false,
			reason:     "blocked",
		},
		{
			name: "deny permission denies access",
			permissions: []PermissionRule{
				{Ref: "refs/heads/*", Action: "read", Group: "Developers", Priority: 50, Project: "test"},
				{Ref: "refs/heads/*", Action: "deny", Group: "Blocked Group", Priority: 100, Project: "test"},
			},
			userGroups: []string{"Developers", "Blocked Group"},
			ref:        "refs/heads/master",
			expected:   false,
			reason:     "denied",
		},
		{
			name: "read permission grants access",
			permissions: []PermissionRule{
				{Ref: "refs/heads/*", Action: "read", Group: "Developers", Priority: 50, Project: "test"},
			},
			userGroups: []string{"Developers"},
			ref:        "refs/heads/master",
			expected:   true,
			reason:     "granted",
		},
		{
			name: "no matching permissions",
			permissions: []PermissionRule{
				{Ref: "refs/heads/*", Action: "read", Group: "Developers", Priority: 50, Project: "test"},
			},
			userGroups: []string{"Other Group"},
			ref:        "refs/heads/master",
			expected:   false,
			reason:     "no matching",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Log(log.INFO, fmt.Sprintf("Testing evaluatePermissions: %s", tt.name))
			log.Log(log.INFO, fmt.Sprintf("User groups: %v, Ref: %s", tt.userGroups, tt.ref))
			
			for i, perm := range tt.permissions {
				log.Log(log.INFO, fmt.Sprintf("Permission[%d]: Ref=%s, Action=%s, Group=%s, Priority=%d", 
					i, perm.Ref, perm.Action, perm.Group, perm.Priority))
			}
			
			result, reason := evaluatePermissions(tt.permissions, tt.userGroups, tt.ref)
			
			log.Log(log.INFO, fmt.Sprintf("Evaluation result: access=%v, reason=%s", result, reason))
			
			if result != tt.expected {
				t.Errorf("evaluatePermissions() = %v, want %v", result, tt.expected)
			}
			
			if !strings.Contains(strings.ToLower(reason), tt.reason) {
				t.Errorf("evaluatePermissions() reason = %v, should contain %v", reason, tt.reason)
			}
		})
	}
	
	log.Log(log.INFO, "=== Finished TestEvaluatePermissions ===")
}

func TestRefPatternMatches(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestRefPatternMatches ===")
	
	tests := []struct {
		name     string
		pattern  string
		ref      string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "refs/heads/master",
			ref:      "refs/heads/master",
			expected: true,
		},
		{
			name:     "wildcard match",
			pattern:  "refs/heads/*",
			ref:      "refs/heads/master",
			expected: true,
		},
		{
			name:     "wildcard no match",
			pattern:  "refs/heads/*",
			ref:      "refs/tags/v1.0",
			expected: false,
		},
		{
			name:     "double wildcard match",
			pattern:  "refs/**",
			ref:      "refs/heads/feature/branch",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Log(log.INFO, fmt.Sprintf("Testing refPatternMatches: pattern=%s, ref=%s", tt.pattern, tt.ref))
			
			result := refPatternMatches(tt.pattern, tt.ref)
			
			log.Log(log.INFO, fmt.Sprintf("Pattern match result: %v", result))
			
			if result != tt.expected {
				t.Errorf("refPatternMatches(%s, %s) = %v, want %v", tt.pattern, tt.ref, result, tt.expected)
			}
		})
	}
	
	log.Log(log.INFO, "=== Finished TestRefPatternMatches ===")
}

// Integration test that tests the full flow
func TestIntegrationFullFlow(t *testing.T) {
	log.Log(log.INFO, "=== Starting TestIntegrationFullFlow ===")
	
	mockServer := createMockGerritServer()
	defer mockServer.Close()
	
	log.Log(log.INFO, "Testing full integration flow with inheritance and BLOCK permissions")
	
	// Test 1: Normal user with access
	log.Log(log.INFO, "Test 1: Normal user (testuser) accessing test-project")
	result1, err1 := CheckAccess(mockServer.URL, "testuser", "test-project", "admin", "token")
	log.Log(log.INFO, fmt.Sprintf("Result 1: access=%v, error=%v", result1, err1))
	
	if err1 != nil {
		t.Errorf("Integration test 1 failed: %v", err1)
	}
	if !result1 {
		t.Errorf("Integration test 1: expected access granted, got denied")
	}
	
	// Test 2: Blocked user should be denied due to BLOCK rule in All-Projects
	log.Log(log.INFO, "Test 2: Blocked user (blockeduser) accessing test-project")
	result2, err2 := CheckAccess(mockServer.URL, "blockeduser", "test-project", "admin", "token")
	log.Log(log.INFO, fmt.Sprintf("Result 2: access=%v, error=%v", result2, err2))
	
	if err2 != nil {
		t.Errorf("Integration test 2 failed: %v", err2)
	}
	if result2 {
		t.Errorf("Integration test 2: expected access denied, got granted")
	}
	
	// Test 3: Special user should always have access
	log.Log(log.INFO, "Test 3: Special user (gerrit-replication) accessing any project")
	result3, err3 := CheckAccess(mockServer.URL, "gerrit-replication", "any-project", "admin", "token")
	log.Log(log.INFO, fmt.Sprintf("Result 3: access=%v, error=%v", result3, err3))
	
	if err3 != nil {
		t.Errorf("Integration test 3 failed: %v", err3)
	}
	if !result3 {
		t.Errorf("Integration test 3: expected access granted, got denied")
	}
	
	log.Log(log.INFO, "=== Finished TestIntegrationFullFlow ===")
}