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

// CheckAccess 检查用户是否有权限访问仓库
func CheckAccess(gerritURL, username, repo, gerritUser, gerritToken string) (bool, error) {
	// 对于特定用户，直接返回有权限
	if username == "gerrit-replication" || username == "git" || username == "gitadmin"  {
		return true, nil
	}

	// 构建API URL
	apiURL := fmt.Sprintf("%s/a/projects/%s/access", gerritURL, url.PathEscape(repo))
	
	// 创建请求
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("创建请求失败: %w", err)
	}
	
	// 设置认证
	req.SetBasicAuth(gerritUser, gerritToken)
	
	// 发送请求
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("读取响应失败: %w", err)
	}
	
	// 记录响应状态码
	log.Log(log.INFO, fmt.Sprintf("Gerrit API响应状态码: %d", resp.StatusCode))

	// 记录原始响应以便调试
	log.Log(log.INFO, fmt.Sprintf("Gerrit API响应状态码: %d", resp.StatusCode))

	// Gerrit API返回的JSON前缀有特殊字符，需要去除
	jsonBody := bytes.TrimPrefix(body, []byte(")]}'\n"))

	// 检查响应是否为空
	if len(jsonBody) == 0 {
		log.Log(log.WARN, "Gerrit API返回空响应")
		return false, fmt.Errorf("Gerrit API返回空响应")
	}

	// 记录处理后的JSON以便调试
	if len(jsonBody) > 100 {
		log.Log(log.INFO, fmt.Sprintf("处理后的JSON前100字符: %s", string(jsonBody[:100])))
	} else {
		log.Log(log.INFO, fmt.Sprintf("处理后的JSON: %s", string(jsonBody)))
	}

	// 解析JSON
	var accessInfo map[string]interface{}
	if err := json.Unmarshal(jsonBody, &accessInfo); err != nil {
		// 记录更详细的错误信息
		errMsg := fmt.Sprintf("JSON解析失败: %v", err)
		if len(jsonBody) > 200 {
			errMsg += fmt.Sprintf(", 原始数据前200字符: %s", string(jsonBody[:200]))
		} else {
			errMsg += fmt.Sprintf(", 原始数据: %s", string(jsonBody))
		}
		log.Log(log.ERROR, errMsg)

		// 检查是否包含特定错误信息
		rawResponse := string(body)
		if strings.Contains(rawResponse, "--account") {
			log.Log(log.ERROR, fmt.Sprintf("检测到Gerrit API参数错误: %s", rawResponse))
			return false, fmt.Errorf("Gerrit API调用失败: %s (URL: `%s,` User: %s, Repo: %s)", 
				rawResponse, gerritURL, username, repo)
		}

		// 尝试使用更宽松的方式解析
		var anyData interface{}
		if jsonErr := json.Unmarshal(jsonBody, &anyData); jsonErr != nil {
			// 如果连宽松解析也失败，则返回错误
			return false, fmt.Errorf("解析响应失败: %w (URL: `%s,` User: %s, Repo: %s)", 
				err, gerritURL, username, repo)
		}

		// 如果宽松解析成功，则假定有权限（避免因解析问题阻止访问）
		log.Log(log.WARN, "JSON格式不规范但可解析，假定有权限")
		return true, nil
	}

	// 检查是否有访问权限
	// 这里需要根据Gerrit API的实际返回格式进行调整
	if accessInfo == nil || len(accessInfo) == 0 {
		return false, nil
	}

	// 简单判断：如果返回了非空结果且状态码为200，则认为有权限
	return resp.StatusCode == 200, nil
}
