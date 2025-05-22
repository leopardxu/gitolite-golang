package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"
)

// HookType 表示钩子类型
type HookType string

const (
	PreReceive  HookType = "pre-receive"
	PostReceive HookType = "post-receive"
	Update      HookType = "update"
	PrePush     HookType = "pre-push"
)

// HookManager 钩子管理器
type HookManager struct {
	HooksDir string
	RepoBase string
}

// NewHookManager 创建新的钩子管理器
func NewHookManager(repoBase, hooksDir string) *HookManager {
	return &HookManager{
		HooksDir: hooksDir,
		RepoBase: repoBase,
	}
}

// InstallHooks 为仓库安装钩子
func (hm *HookManager) InstallHooks(repoPath string) error {
	// 确保钩子目录存在
	hooksDir := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("创建钩子目录失败: %w", err)
	}

	// 安装各类钩子
	hookTypes := []HookType{PreReceive, PostReceive, Update}
	for _, hookType := range hookTypes {
		if err := hm.installHook(repoPath, hookType); err != nil {
			return err
		}
	}

	log.Log(log.INFO, fmt.Sprintf("成功为仓库 %s 安装钩子", repoPath))
	return nil
}

// installHook 安装单个钩子
func (hm *HookManager) installHook(repoPath string, hookType HookType) error {
	// 源钩子路径（全局钩子模板）
	srcHookPath := filepath.Join(hm.HooksDir, string(hookType))

	// 目标钩子路径（仓库特定钩子）
	dstHookPath := filepath.Join(repoPath, "hooks", string(hookType))

	// 检查源钩子是否存在
	if _, err := os.Stat(srcHookPath); os.IsNotExist(err) {
		// 源钩子不存在，创建一个简单的钩子脚本
		content := fmt.Sprintf("#!/bin/sh\n# 自动生成的 %s 钩子\nexit 0\n", hookType)
		if err := os.WriteFile(dstHookPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("创建钩子脚本失败: %w", err)
		}
	} else {
		// 源钩子存在，复制到目标路径
		srcContent, err := os.ReadFile(srcHookPath)
		if err != nil {
			return fmt.Errorf("读取源钩子失败: %w", err)
		}

		if err := os.WriteFile(dstHookPath, srcContent, 0755); err != nil {
			return fmt.Errorf("写入目标钩子失败: %w", err)
		}
	}

	return nil
}

// ExecuteHook 执行钩子
func (hm *HookManager) ExecuteHook(repoPath string, hookType HookType, args ...string) error {
	hookPath := filepath.Join(repoPath, "hooks", string(hookType))

	// 检查钩子是否存在
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		// 钩子不存在，视为成功
		return nil
	}

	// 执行钩子
	cmd := exec.Command(hookPath, args...)
	cmd.Dir = repoPath
	cmd.Env = os.Environ()

	// 添加仓库相关环境变量
	repoName := filepath.Base(repoPath)
	repoName = strings.TrimSuffix(repoName, ".git")
	cmd.Env = append(cmd.Env, fmt.Sprintf("GL_REPO=%s", repoName))

	// 执行命令并获取输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("执行钩子 %s 失败: %v, 输出: %s", hookType, err, output))
		return fmt.Errorf("钩子执行失败: %w, 输出: %s", err, output)
	}

	log.Log(log.INFO, fmt.Sprintf("成功执行钩子 %s, 输出: %s", hookType, output))
	return nil
}

// CreateCustomHook 创建自定义钩子
func (hm *HookManager) CreateCustomHook(hookType HookType, content string) error {
	// 确保钩子目录存在
	if err := os.MkdirAll(hm.HooksDir, 0755); err != nil {
		return fmt.Errorf("创建钩子目录失败: %w", err)
	}

	// 钩子路径
	hookPath := filepath.Join(hm.HooksDir, string(hookType))

	// 写入钩子内容
	if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("写入钩子内容失败: %w", err)
	}

	log.Log(log.INFO, fmt.Sprintf("成功创建自定义钩子 %s", hookType))
	return nil
}

// InstallHooksForAllRepos 为所有仓库安装钩子
func (hm *HookManager) InstallHooksForAllRepos() error {
	// 遍历仓库基础目录
	return filepath.Walk(hm.RepoBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 检查是否是Git仓库（目录名以.git结尾或者包含HEAD文件）
		if info.IsDir() && (strings.HasSuffix(path, ".git") || fileExists(filepath.Join(path, "HEAD"))) {
			if err := hm.InstallHooks(path); err != nil {
				log.Log(log.WARN, fmt.Sprintf("为仓库 %s 安装钩子失败: %v", path, err))
			}
		}

		return nil
	})
}

// fileExists 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}