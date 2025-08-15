package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gitolite-golang/internal/log"
)

// AccessInfo 用户访问信息结构
type AccessInfo struct {
	Timestamp    time.Time `json:"timestamp"`               // 访问时间
	User         string    `json:"user"`                    // 用户名
	Repository   string    `json:"repository"`              // 仓库名
	Operation    string    `json:"operation"`               // 操作类型 (clone, push, pull等)
	Command      string    `json:"command"`                 // 原始Git命令
	ClientIP     string    `json:"client_ip"`               // 客户端IP地址
	SSHClient    string    `json:"ssh_client"`              // SSH客户端信息
	ConnectionID string    `json:"connection_id"`           // 连接ID (进程ID)
	Success      bool      `json:"success"`                 // 操作是否成功
	ErrorMessage string    `json:"error_message,omitempty"` // 错误信息（如果有）
}

// AuditLogger 审计日志记录器
type AuditLogger struct {
	logPath    string
	enabled    bool
	consoleOut bool
}

// NewAuditLogger 创建新的审计日志记录器
func NewAuditLogger(logPath string, enabled bool, consoleOut bool) *AuditLogger {
	return &AuditLogger{
		logPath:    logPath,
		enabled:    enabled,
		consoleOut: consoleOut,
	}
}

// CollectAccessInfo 收集用户访问信息
func CollectAccessInfo(user, repo, operation, command string) *AccessInfo {
	// 获取客户端IP信息
	clientIP := getClientIP()
	sshClient := getSSHClientInfo()
	connectionID := fmt.Sprintf("%d", os.Getpid())

	return &AccessInfo{
		Timestamp:    time.Now(),
		User:         user,
		Repository:   repo,
		Operation:    operation,
		Command:      command,
		ClientIP:     clientIP,
		SSHClient:    sshClient,
		ConnectionID: connectionID,
		Success:      true, // 默认成功，可以后续更新
	}
}

// LogAccess 记录访问信息
func (al *AuditLogger) LogAccess(info *AccessInfo) {
	if !al.enabled {
		return
	}

	// 按配置输出到控制台
	if al.consoleOut {
		al.printStructuredInfo(info)
	}

	// 记录到审计日志文件（当配置了路径时）
	if al.logPath != "" {
		al.writeToAuditLog(info)
	}
}

// printStructuredInfo 结构化输出访问信息到控制台
func (al *AuditLogger) printStructuredInfo(info *AccessInfo) {
	// 创建格式化的输出，输出到stderr避免干扰Git协议
	fmt.Fprintf(os.Stderr, "\n=== Git Access Information ===\n")
	fmt.Fprintf(os.Stderr, "Time:         %s\n", info.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(os.Stderr, "User:         %s\n", info.User)
	fmt.Fprintf(os.Stderr, "Repository:   %s\n", info.Repository)
	fmt.Fprintf(os.Stderr, "Operation:    %s\n", info.Operation)
	fmt.Fprintf(os.Stderr, "Command:      %s\n", info.Command)
	fmt.Fprintf(os.Stderr, "Client IP:    %s\n", info.ClientIP)
	fmt.Fprintf(os.Stderr, "SSH Client:   %s\n", info.SSHClient)
	fmt.Fprintf(os.Stderr, "Connection:   %s\n", info.ConnectionID)
	fmt.Fprintf(os.Stderr, "Status:       %s\n", getStatusString(info.Success))
	if info.ErrorMessage != "" {
		fmt.Fprintf(os.Stderr, "Error:        %s\n", info.ErrorMessage)
	}
	fmt.Fprintf(os.Stderr, "==============================\n\n")
}

// writeToAuditLog 写入审计日志文件
func (al *AuditLogger) writeToAuditLog(info *AccessInfo) {
	// 将访问信息序列化为JSON
	jsonData, err := json.Marshal(info)
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to marshal audit info: %v", err))
		return
	}

	// 写入日志文件
	file, err := os.OpenFile(al.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to open audit log file: %v", err))
		return
	}
	defer file.Close()

	// 写入JSON数据和换行符
	if _, err := file.WriteString(string(jsonData) + "\n"); err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to write audit log: %v", err))
	}
}

// UpdateAccessResult 更新访问结果
func (info *AccessInfo) UpdateResult(success bool, errorMsg string) {
	info.Success = success
	info.ErrorMessage = errorMsg
}

// getClientIP 获取客户端IP地址
func getClientIP() string {
	// SSH_CLIENT 环境变量格式: "client_ip client_port server_port"
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) > 0 {
			return parts[0] // 返回客户端IP
		}
	}

	// 尝试其他环境变量
	if remoteAddr := os.Getenv("SSH_CONNECTION"); remoteAddr != "" {
		parts := strings.Fields(remoteAddr)
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return "unknown"
}

// getSSHClientInfo 获取SSH客户端信息
func getSSHClientInfo() string {
	// SSH_CLIENT 环境变量包含完整的连接信息
	if sshClient := os.Getenv("SSH_CLIENT"); sshClient != "" {
		return sshClient
	}

	// SSH_CONNECTION 也包含连接信息
	if sshConn := os.Getenv("SSH_CONNECTION"); sshConn != "" {
		return sshConn
	}

	return "unknown"
}

// getStatusString 获取状态字符串
func getStatusString(success bool) string {
	if success {
		return "SUCCESS"
	}
	return "FAILED"
}

// GetOperationType 根据Git命令获取操作类型
func GetOperationType(command string) string {
	switch {
	case strings.Contains(command, "git-upload-pack"):
		return "clone/pull"
	case strings.Contains(command, "git-receive-pack"):
		return "push"
	case strings.Contains(command, "git-upload-archive"):
		return "archive"
	default:
		return "other"
	}
}
