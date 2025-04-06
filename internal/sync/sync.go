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
	// 读取现有的 authorized_keys 文件
	existingData, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取现有 authorized_keys 文件失败: %v", err)
	}

	// 解析现有的密钥
	existingKeys := make(map[string]bool)
	if len(existingData) > 0 {
		for _, line := range strings.Split(string(existingData), "\n") {
			if line != "" {
				existingKeys[line] = true
			}
		}
	}

	// 合并新密钥，避免重复
	var allKeys []string
	for _, key := range keys {
		if !existingKeys[key] {
			allKeys = append(allKeys, key)
			existingKeys[key] = true
		}
	}

	// 将现有密钥添加到结果中
	for line := range existingKeys {
		if line != "" {
			allKeys = append(allKeys, line)
		}
	}

	// 写入合并后的密钥
	data := []byte(strings.Join(allKeys, "\n") + "\n")
	return ioutil.WriteFile(path, data, 0600)
}

func ConvertToGitoliteFormat(keys []GerritSSHKey) []string {
	var gitoliteKeys []string
	for _, key := range keys {
		// 确保 SSH 密钥和用户名都不为空
		if key.SSHKey == "" || key.Username == "" {
			continue
		}

		// 使用正确的格式：包含用户名和 SSH 密钥
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

	// 获取所有用户列表
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/a/accounts/?q=is:active&o=DETAILS", gerritURL), nil)
	if err != nil {
		return nil, fmt.Errorf("创建用户列表请求失败: %v", err)
	}

	req.SetBasicAuth(gerritUser, apiToken)
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取用户列表失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取用户列表时状态码异常: %d, 响应: %s", resp.StatusCode, string(body))
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取用户列表响应失败: %v", err)
	}

	// 移除Gerrit魔术前缀 - 修复前缀检测逻辑
	if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}}'" {
		rawBody = rawBody[4:]
	} else if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}'" {
		rawBody = rawBody[4:]
	}

	// 尝试解析为数组
	var usersArray []map[string]interface{}
	if err := json.Unmarshal(rawBody, &usersArray); err != nil {
		return nil, fmt.Errorf("解析用户列表失败: %v, 原始响应: %s", err, string(rawBody))
	}

	// 处理用户数组
	var allKeys []GerritSSHKey
	for _, userObj := range usersArray {
		username, ok := userObj["username"].(string)
		if !ok || username == "" {
			// 尝试从name或email获取用户名
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

		// 获取用户的SSH密钥
		keys, err := fetchUserSSHKeys(client, gerritURL, gerritUser, apiToken, int(accountID), username)
		if err != nil {
			fmt.Printf("获取用户 %s 的SSH密钥失败: %v\n", username, err)
			continue
		}

		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

// 辅助函数：获取单个用户的SSH密钥
func fetchUserSSHKeys(client *http.Client, gerritURL, gerritUser, apiToken string, accountID int, username string) ([]GerritSSHKey, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/a/accounts/%d/sshkeys", gerritURL, accountID), nil)
	if err != nil {
		return nil, fmt.Errorf("创建SSH密钥请求失败: %v", err)
	}

	req.SetBasicAuth(gerritUser, apiToken)
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取SSH密钥失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取SSH密钥时状态码异常: %d, 响应: %s", resp.StatusCode, string(body))
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取SSH密钥响应失败: %v", err)
	}

	// 移除Gerrit魔术前缀 - 修复前缀检测逻辑
	if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}}'" {
		rawBody = rawBody[4:]
	} else if len(rawBody) > 4 && string(rawBody[0:4]) == ")]}'" {
		rawBody = rawBody[4:]
	}

	// 尝试解析为数组
	var keysArray []map[string]interface{}
	if err := json.Unmarshal(rawBody, &keysArray); err != nil {
		return nil, fmt.Errorf("解析SSH密钥失败: %v, 原始响应: %s", err, string(rawBody))
	}

	var keys []GerritSSHKey
	for _, keyObj := range keysArray {
		sshKey, ok := keyObj["ssh_public_key"].(string)
		if !ok || sshKey == "" {
			// 尝试其他可能的字段名
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
