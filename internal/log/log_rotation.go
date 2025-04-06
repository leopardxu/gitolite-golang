package log

import (
	"fmt"
	"os"
	"time"
)

// RotateLog 按天或周分割日志文件
func RotateLog(logPath string, rotation string) error {
	now := time.Now()
	var newLogPath string

	switch rotation {
	case "daily":
		newLogPath = logPath + "." + now.Format("2006-01-02")
	case "weekly":
		year, week := now.ISOWeek()
		newLogPath = logPath + "." + fmt.Sprintf("%d-W%02d", year, week)
	default:
		return nil
	}

	if err := os.Rename(logPath, newLogPath); err != nil {
		return err
	}

	return nil
}
