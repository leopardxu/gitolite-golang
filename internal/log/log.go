package log

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	INFO LogLevel = iota
	WARN
	ERROR
)

var (
	logger   *log.Logger
	logLevel LogLevel
	mu       sync.Mutex
)

// LogConfig 日志配置
type LogConfig struct {
	Path     string
	Level    LogLevel
	Rotation string
	Compress bool
	MaxAge   int
}

var currentConfig LogConfig

// Init 初始化日志模块
func Init(logPath string, level LogLevel) error {
	return InitWithConfig(LogConfig{
		Path:  logPath,
		Level: level,
	})
}

// InitWithConfig 使用完整配置初始化日志模块
func InitWithConfig(config LogConfig) error {
	// 确保日志目录存在
	logDir := filepath.Dir(config.Path)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// 打开日志文件
	file, err := os.OpenFile(config.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// 初始化日志记录器
	logger = log.New(file, "", log.LstdFlags)
	logLevel = config.Level
	currentConfig = config

	// 检查是否需要轮转日志
	if config.Rotation != "" {
		go startLogRotation()
	}

	return nil
}

// startLogRotation 启动日志轮转任务
func startLogRotation() {
	ticker := time.NewTicker(24 * time.Hour) // 每天检查一次
	defer ticker.Stop()

	for range ticker.C {
		rotateLogIfNeeded()
	}
}

// rotateLogIfNeeded 根据配置轮转日志
func rotateLogIfNeeded() {
	// 检查是否需要轮转
	need, newLogPath := needRotation(currentConfig.Path, currentConfig.Rotation)
	if !need {
		return
	}

	// 关闭当前日志文件
	mu.Lock()
	defer mu.Unlock()

	// 轮转日志
	if err := RotateLog(currentConfig.Path, currentConfig.Rotation); err != nil {
		log.Printf("日志轮转失败: %v\n", err)
		return
	}

	// 如果需要压缩
	if currentConfig.Compress {
		go func() {
			if err := CompressLog(newLogPath); err != nil {
				log.Printf("日志压缩失败: %v\n", err)
			}
		}()
	}

	// 清理过期日志
	if currentConfig.MaxAge > 0 {
		go cleanupOldLogs(filepath.Dir(currentConfig.Path), currentConfig.MaxAge)
	}

	// 重新打开日志文件
	file, err := os.OpenFile(currentConfig.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("重新打开日志文件失败: %v\n", err)
		return
	}

	logger = log.New(file, "", log.LstdFlags)
}

// needRotation 检查是否需要轮转日志
func needRotation(logPath, rotation string) (bool, string) {
	now := time.Now()
	var newLogPath string

	switch rotation {
	case "daily":
		newLogPath = logPath + "." + now.Format("2006-01-02")
		// 检查今天的日志文件是否已经存在
		if _, err := os.Stat(newLogPath); os.IsNotExist(err) {
			return true, newLogPath
		}
	case "weekly":
		year, week := now.ISOWeek()
		newLogPath = logPath + "." + fmt.Sprintf("%d-W%02d", year, week)
		// 检查本周的日志文件是否已经存在
		if _, err := os.Stat(newLogPath); os.IsNotExist(err) {
			return true, newLogPath
		}
	}

	return false, ""
}

// cleanupOldLogs 清理过期日志
func cleanupOldLogs(logDir string, maxAge int) {
	cutoff := time.Now().AddDate(0, 0, -maxAge)

	// 遍历日志目录
	files, err := os.ReadDir(logDir)
	if err != nil {
		log.Printf("读取日志目录失败: %v\n", err)
		return
	}

	for _, file := range files {
		// 跳过目录
		if file.IsDir() {
			continue
		}

		// 获取文件信息
		info, err := file.Info()
		if err != nil {
			continue
		}

		// 检查是否是日志文件（以.log开头或包含日期格式）
		name := file.Name()
		if !strings.HasSuffix(name, ".log") && !strings.Contains(name, ".log.") {
			continue
		}

		// 检查文件修改时间是否早于截止日期
		if info.ModTime().Before(cutoff) {
			filePath := filepath.Join(logDir, name)
			if err := os.Remove(filePath); err != nil {
				log.Printf("删除过期日志文件失败: %v\n", err)
			}
		}
	}
}

// Log 记录日志
func Log(level LogLevel, message string) {
	mu.Lock()
	defer mu.Unlock()

	// 检查 logger 是否已初始化，如果没有则初始化为标准输出
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	if level < logLevel {
		return
	}

	var levelStr string
	switch level {
	case INFO:
		levelStr = "INFO"
	case WARN:
		levelStr = "WARN"
	case ERROR:
		levelStr = "ERROR"
	}

	logger.Printf("[%s] %s\n", levelStr, message)
}
