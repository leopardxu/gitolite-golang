package sync

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/robfig/cron/v3"
)

type GerritSSHKey struct {
	Username string `json:"username"`
	SSHKey   string `json:"ssh_public_key"` // 确保字段名与 Gerrit API 响应匹配
}

// FetchGerritSSHKeys 调用 Gerrit API 获取公钥
func StartSyncTask(gerritURL, apiUser, apiToken, authorizedKeysPath string) {
	c := cron.New()
	c.AddFunc("@every 5m", func() {
		keys, err := FetchGerritSSHKeys(gerritURL, apiUser, apiToken)
		if err != nil {
			log.Printf("Failed to fetch Gerrit SSH keys: %v\n", err)
			return
		}

		gitoliteKeys := ConvertToGitoliteFormat(keys)
		if err := WriteAuthorizedKeys(gitoliteKeys, authorizedKeysPath); err != nil {
			log.Printf("Failed to write authorized_keys: %v\n", err)
			return
		}

		log.Println("Successfully synchronized SSH keys from Gerrit")
	})
	c.Start()
}
func WriteAuthorizedKeys(keys []string, path string) error {
	// Read existing authorized_keys file
	existingData, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read existing authorized_keys file: %v", err)
	}

	// Parse existing keys
	existingKeys := make(map[string]bool)
	if len(existingData) > 0 {
		for _, line := range strings.Split(string(existingData), "\n") {
			if line != "" {
				existingKeys[line] = true
			}
		}
	}

	// Merge new keys, avoid duplicates
	var allKeys []string
	for _, key := range keys {
		if !existingKeys[key] {
			allKeys = append(allKeys, key)
			existingKeys[key] = true
		}
	}

	// Add existing keys to the result
	for line := range existingKeys {
		if line != "" {
			allKeys = append(allKeys, line)
		}
	}

	// Write merged keys
	data := []byte(strings.Join(allKeys, "\n") + "\n")
	return ioutil.WriteFile(path, data, 0600)
}

func ConvertToGitoliteFormat(keys []GerritSSHKey) []string {
	var gitoliteKeys []string
	for _, key := range keys {
		// Ensure SSH key and username are not empty
		if key.SSHKey == "" || key.Username == "" {
			continue
		}

		// Use correct format: include username and SSH key
		gitoliteKey := fmt.Sprintf(
			`command="gitolite-shell %s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s`,
			key.Username,
			key.SSHKey,
		)
		gitoliteKeys = append(gitoliteKeys, gitoliteKey)
	}
	return gitoliteKeys
}

func FetchGerritSSHKeys(gerritURL, gerritUser, apiToken string) ([]GerritSSHKey, error) {
	client := &http.Client{}

	// Get all user list
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/a/accounts/?q=is:active&o=DETAILS", gerritURL), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user list request: %v", err)
	}

	req.SetBasicAuth(gerritUser, apiToken)
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user list: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("abnormal status code when getting user list: %d, response: %s", resp.StatusCode, string(body))
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user list response: %v", err)
	}

	// Remove Gerrit magic prefix - fix prefix detection logic
	if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}}'" {
		rawBody = rawBody[4:]
	} else if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}'" {
		rawBody = rawBody[4:]
	}

	// Try to parse as array
	var usersArray []map[string]interface{}
	if err := json.Unmarshal(rawBody, &usersArray); err != nil {
		return nil, fmt.Errorf("failed to parse user list: %v, original response: %s", err, string(rawBody))
	}

	// Process user array
	var allKeys []GerritSSHKey
	for _, userObj := range usersArray {
		username, ok := userObj["username"].(string)
		if !ok || username == "" {
			// Try to get username from name or email
			if name, ok := userObj["name"].(string); ok && name != "" {
				username = name
			} else if email, ok := userObj["email"].(string); ok && email != "" {
				parts := strings.Split(email, "@")
				username = parts[0]
			} else {
				continue
			}
		}

		accountID, ok := userObj["_account_id"].(float64)
		if !ok {
			continue
		}

		// Get user's SSH keys
		keys, err := fetchUserSSHKeys(client, gerritURL, gerritUser, apiToken, int(accountID), username)
		if err != nil {
			fmt.Printf("Failed to get SSH keys for user %s: %v\n", username, err)
			continue
		}

		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

// Helper function: get SSH keys for a single user
func fetchUserSSHKeys(client *http.Client, gerritURL, gerritUser, apiToken string, accountID int, username string) ([]GerritSSHKey, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/a/accounts/%d/sshkeys", gerritURL, accountID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH key request: %v", err)
	}

	req.SetBasicAuth(gerritUser, apiToken)
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH keys: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("abnormal status code when getting SSH keys: %d, response: %s", resp.StatusCode, string(body))
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key response: %v", err)
	}

	// Remove Gerrit magic prefix - fix prefix detection logic
	if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}}'" {
		rawBody = rawBody[4:]
	} else if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}'" {
		rawBody = rawBody[4:]
	}

	// Try to parse as array
	var keysArray []map[string]interface{}
	if err := json.Unmarshal(rawBody, &keysArray); err != nil {
		return nil, fmt.Errorf("failed to parse SSH keys: %v, original response: %s", err, string(rawBody))
	}

	var keys []GerritSSHKey
	for _, keyObj := range keysArray {
		sshKey, ok := keyObj["ssh_public_key"].(string)
		if !ok || sshKey == "" {
			// Try other possible field names
			if key, ok := keyObj["key"].(string); ok && key != "" {
				sshKey = key
			} else {
				continue
			}
		}

		keys = append(keys, GerritSSHKey{
			Username: username,
			SSHKey:   sshKey,
		})
	}

	return keys, nil
}
