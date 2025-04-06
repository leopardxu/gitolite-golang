package log

import (
	"log"
	"os"
	"sync"
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

// Init 初始化日志模块
func Init(logPath string, level LogLevel) error {
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	logger = log.New(file, "", log.LstdFlags)
	logLevel = level
	return nil
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
