package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"
)

// HookType represents hook type
type HookType string

// Define supported hook types
const (
	PreReceive  HookType = "pre-receive"
	PostReceive HookType = "post-receive"
	Update      HookType = "update"
	PrePush     HookType = "pre-push"
)

// HookManager hook manager
type HookManager struct {
	HooksDir string
	RepoBase string
}

// NewHookManager creates a new hook manager
func NewHookManager(repoBase, hooksDir string) *HookManager {
	return &HookManager{
		HooksDir: hooksDir,
		RepoBase: repoBase,
	}
}

// InstallHooks installs hooks for repository
func (hm *HookManager) InstallHooks(repoPath string) error {
	// Ensure hooks directory exists
	hooksDir := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	// Install various hooks
	hookTypes := []HookType{PreReceive, PostReceive, Update}
	for _, hookType := range hookTypes {
		if err := hm.installHook(repoPath, hookType); err != nil {
			return err
		}
	}

	log.Log(log.INFO, fmt.Sprintf("Successfully installed hooks for repository %s", repoPath))
	return nil
}

// installHook installs a single hook
func (hm *HookManager) installHook(repoPath string, hookType HookType) error {
	// Source hook path (global hook template)
	srcHookPath := filepath.Join(hm.HooksDir, string(hookType))

	// Destination hook path (repository specific hook)
	dstHookPath := filepath.Join(repoPath, "hooks", string(hookType))

	// Check if source hook exists
	if _, err := os.Stat(srcHookPath); os.IsNotExist(err) {
		// Source hook doesn't exist, create a simple hook script
		content := fmt.Sprintf("#!/bin/sh\n# Auto-generated %s hook\nexit 0\n", hookType)
		if err := os.WriteFile(dstHookPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("failed to create hook script: %w", err)
		}
	} else {
		// Source hook exists, copy to destination path
		srcContent, err := os.ReadFile(srcHookPath)
		if err != nil {
			return fmt.Errorf("failed to read source hook: %w", err)
		}

		if err := os.WriteFile(dstHookPath, srcContent, 0755); err != nil {
			return fmt.Errorf("failed to write destination hook: %w", err)
		}
	}

	return nil
}

// ExecuteHook executes hook
func (hm *HookManager) ExecuteHook(repoPath string, hookType HookType, args ...string) error {
	hookPath := filepath.Join(repoPath, "hooks", string(hookType))

	// Check if hook exists
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		// Hook doesn't exist, consider as success
		return nil
	}

	// Execute hook
	cmd := exec.Command(hookPath, args...)
	cmd.Dir = repoPath
	cmd.Env = os.Environ()

	// Add repository related environment variables
	repoName := filepath.Base(repoPath)
	repoName = strings.TrimSuffix(repoName, ".git")
	cmd.Env = append(cmd.Env, fmt.Sprintf("GL_REPO=%s", repoName))

	// Execute command and get output
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to execute hook %s: %v, output: %s", hookType, err, output))
		return fmt.Errorf("hook execution failed: %w, output: %s", err, output)
	}

	log.Log(log.INFO, fmt.Sprintf("Successfully executed hook %s, output: %s", hookType, output))
	return nil
}

// CreateCustomHook creates custom hook
func (hm *HookManager) CreateCustomHook(hookType HookType, content string) error {
	// Ensure hooks directory exists
	if err := os.MkdirAll(hm.HooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	// Hook path
	hookPath := filepath.Join(hm.HooksDir, string(hookType))

	// Write hook content
	if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("failed to write hook content: %w", err)
	}

	log.Log(log.INFO, fmt.Sprintf("Successfully created custom hook %s", hookType))
	return nil
}

// InstallHooksForAllRepos installs hooks for all repositories
func (hm *HookManager) InstallHooksForAllRepos() error {
	// Traverse repository base directory
	return filepath.Walk(hm.RepoBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if it's a Git repository (directory name ends with .git or contains HEAD file)
		if info.IsDir() && (strings.HasSuffix(path, ".git") || fileExists(filepath.Join(path, "HEAD"))) {
			if err := hm.InstallHooks(path); err != nil {
				log.Log(log.WARN, fmt.Sprintf("Failed to install hooks for repository %s: %v", path, err))
			}
		}

		return nil
	})
}

// fileExists checks if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}