package validator

import (
	"errors"
	"path/filepath"
	"strings"
)

// ValidateRepoName 验证仓库名称，防止路径遍历攻击
func ValidateRepoName(repo string) error {
	// 检查是否包含路径遍历尝试
	if strings.Contains(repo, "..") {
		return errors.New("仓库名称包含非法字符序列 '..'")
	}
	
	// 检查是否是绝对路径
	if filepath.IsAbs(repo) {
		return errors.New("仓库名称不能是绝对路径")
	}
	
	// 检查是否包含特殊字符
	invalidChars := []string{"\\", ";", "&", "|", ">", "<", "*", "?", "`", "$", "!", "#"}
	for _, char := range invalidChars {
		if strings.Contains(repo, char) {
			return errors.New("仓库名称包含非法字符: " + char)
		}
	}
	
	return nil
}

// ValidatePath 确保路径安全，防止目录遍历
func ValidatePath(basePath, relativePath string) (string, error) {
	// 构建完整路径
	fullPath := filepath.Join(basePath, relativePath)
	
	// 规范化路径
	fullPath = filepath.Clean(fullPath)
	
	// 确保结果路径仍在基础路径下
	if !strings.HasPrefix(fullPath, basePath) {
		return "", errors.New("路径超出了允许的范围")
	}
	
	return fullPath, nil
}