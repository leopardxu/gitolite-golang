package gerrit

import (
	"bytes"
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
	if username == "gerrit-replication" || username == "git" || username == "gitadmin"  {
		return true, nil
	}

	// Build API URL
	apiURL := fmt.Sprintf("%s/a/projects/%s/access", gerritURL, url.PathEscape(repo))
	
	// Create request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set authentication
	req.SetBasicAuth(gerritUser, gerritToken)
	
	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}
	
	// Log response status code
	log.Log(log.INFO, fmt.Sprintf("Gerrit API response status code: %d", resp.StatusCode))

	// Log original response for debugging
	log.Log(log.INFO, fmt.Sprintf("Gerrit API response status code: %d", resp.StatusCode))

	// Gerrit API JSON response has special prefix characters that need to be removed
	jsonBody := bytes.TrimPrefix(body, []byte(")]}'\n"))

	// Check if response is empty
	if len(jsonBody) == 0 {
		log.Log(log.WARN, "Gerrit API returned empty response")
		return false, fmt.Errorf("Gerrit API returned empty response")
	}

	// Log processed JSON for debugging
	if len(jsonBody) > 100 {
		log.Log(log.INFO, fmt.Sprintf("Processed JSON first 100 characters: %s", string(jsonBody[:100])))
	} else {
		log.Log(log.INFO, fmt.Sprintf("Processed JSON: %s", string(jsonBody)))
	}

	// Parse JSON
	var accessInfo map[string]interface{}
	if err := json.Unmarshal(jsonBody, &accessInfo); err != nil {
		// Log more detailed error information
		errMsg := fmt.Sprintf("JSON parsing failed: %v", err)
		if len(jsonBody) > 200 {
			errMsg += fmt.Sprintf(", original data first 200 characters: %s", string(jsonBody[:200]))
		} else {
			errMsg += fmt.Sprintf(", original data: %s", string(jsonBody))
		}
		log.Log(log.ERROR, errMsg)

		// Check if it contains specific error information
		rawResponse := string(body)
		if strings.Contains(rawResponse, "--account") {
			log.Log(log.ERROR, fmt.Sprintf("Detected Gerrit API parameter error: %s", rawResponse))
			return false, fmt.Errorf("Gerrit API call failed: %s (URL: `%s,` User: %s, Repo: %s)", 
				rawResponse, gerritURL, username, repo)
		}

		// Try parsing in a more lenient way
		var anyData interface{}
		if jsonErr := json.Unmarshal(jsonBody, &anyData); jsonErr != nil {
			// If even lenient parsing fails, return an error
			return false, fmt.Errorf("Failed to parse response: %w (URL: `%s,` User: %s, Repo: %s)", 
				err, gerritURL, username, repo)
		}

		// If lenient parsing succeeds, assume permission is granted (to avoid blocking access due to parsing issues)
		log.Log(log.WARN, "JSON format is non-standard but parseable, assuming permission is granted")
		return true, nil
	}

	// Check if access permission exists
	if accessInfo == nil || len(accessInfo) == 0 {
		return false, nil
	}

	// Check local permissions for the specific user
	if local, ok := accessInfo["local"].(map[string]interface{}); ok {
		// Check refs/* permissions
		if refs, ok := local["refs/*"].(map[string]interface{}); ok {
			if permissions, ok := refs["permissions"].(map[string]interface{}); ok {
				if read, ok := permissions["read"].(map[string]interface{}); ok {
					if rules, ok := read["rules"].(map[string]interface{}); ok {
						// Check if user has explicit DENY rule
						userKey := fmt.Sprintf("user:%s", username)
						if userRule, ok := rules[userKey].(map[string]interface{}); ok {
							if action, ok := userRule["action"].(string); ok && action == "DENY" {
								log.Log(log.INFO, fmt.Sprintf("User %s has explicit DENY rule for repository %s", username, repo))
								return false, nil
							}
						}
					}
				}
			}
		}
	}

	// If no explicit DENY rule found and status code is 200, consider having permission
	return resp.StatusCode == 200, nil
}
