package mirror

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gitolite-golang/internal/log"
)

// MirrorTarget represents a mirror target configuration
type MirrorTarget struct {
	Name     string `yaml:"name"`     // Name of the mirror target
	URL      string `yaml:"url"`      // URL of the mirror target (e.g., ssh://git@mirror-server/path/to/repo.git)
	Enabled  bool   `yaml:"enabled"`  // Whether this mirror target is enabled
	Async    bool   `yaml:"async"`    // Whether to push asynchronously
	Timeout  int    `yaml:"timeout"`  // Timeout in seconds for mirror push operation
	AllRepos bool   `yaml:"all_repos"` // Whether to mirror all repositories
	Repos    []string `yaml:"repos"`  // List of repositories to mirror (if all_repos is false)
}

// MirrorConfig represents the mirror configuration
type MirrorConfig struct {
	Enabled  bool           `yaml:"enabled"`  // Whether mirroring is enabled
	Targets  []MirrorTarget `yaml:"targets"` // List of mirror targets
	Schedule string         `yaml:"schedule"` // Cron schedule expression for automatic mirroring
}

// PushToMirror pushes repository changes to a mirror target
func PushToMirror(repoPath string, target MirrorTarget) error {
	log.Log(log.INFO, fmt.Sprintf("Pushing repository %s to mirror %s", repoPath, target.Name))

	// Build git push command
	cmd := exec.Command("git", "push", "--mirror", target.URL)
	cmd.Dir = repoPath

	// Set timeout if specified
	var timeout time.Duration
	if target.Timeout > 0 {
		timeout = time.Duration(target.Timeout) * time.Second
	} else {
		timeout = 5 * time.Minute // Default timeout: 5 minutes
	}

	// Execute command with timeout
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Start command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start git push command: %w", err)
	}

	// Create a channel for command completion
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for command completion or timeout
	select {
	case err := <-done:
		if err != nil {
			log.Log(log.ERROR, fmt.Sprintf("Failed to push to mirror %s: %v, output: %s", 
				target.Name, err, out.String()))
			return fmt.Errorf("mirror push failed: %w, output: %s", err, out.String())
		}
		log.Log(log.INFO, fmt.Sprintf("Successfully pushed to mirror %s, output: %s", 
			target.Name, out.String()))
		return nil
	case <-time.After(timeout):
		// Kill the process if it times out
		cmd.Process.Kill()
		return fmt.Errorf("mirror push timed out after %v seconds", target.Timeout)
	}
}

// ShouldMirrorRepo checks if a repository should be mirrored to a target
func ShouldMirrorRepo(repoName string, target MirrorTarget) bool {
	// If all repositories should be mirrored, return true
	if target.AllRepos {
		return true
	}

	// Check if repository is in the list of repositories to mirror
	for _, repo := range target.Repos {
		// Exact match
		if repo == repoName {
			return true
		}

		// Wildcard match (e.g., "group/*")
		if strings.HasSuffix(repo, "/*") {
			prefix := strings.TrimSuffix(repo, "/*")
			if strings.HasPrefix(repoName, prefix+"/") {
				return true
			}
		}
	}

	return false
}

// MirrorRepository mirrors a repository to all configured targets
func MirrorRepository(repoPath string, repoName string, config MirrorConfig, async bool) error {
	// If mirroring is not enabled, return immediately
	if !config.Enabled || len(config.Targets) == 0 {
		return nil
	}

	log.Log(log.INFO, fmt.Sprintf("Starting mirror operation for repository %s", repoName))

	// Iterate through all mirror targets
	for _, target := range config.Targets {
		// Skip disabled targets
		if !target.Enabled {
			continue
		}

		// Check if this repository should be mirrored to this target
		if !ShouldMirrorRepo(repoName, target) {
			log.Log(log.INFO, fmt.Sprintf("Repository %s is not configured for mirroring to %s", 
				repoName, target.Name))
			continue
		}

		// If async is requested and target supports async, push in a goroutine
		if async && target.Async {
			go func(t MirrorTarget) {
				if err := PushToMirror(repoPath, t); err != nil {
					log.Log(log.ERROR, fmt.Sprintf("Async mirror push failed: %v", err))
				}
			}(target)
		} else {
			// Push synchronously
			if err := PushToMirror(repoPath, target); err != nil {
				log.Log(log.ERROR, fmt.Sprintf("Mirror push failed: %v", err))
				// Continue with other targets even if one fails
			}
		}
	}

	return nil
}

// CreateMirrorPostReceiveHook creates a post-receive hook for mirroring
func CreateMirrorPostReceiveHook(hooksDir string) error {
	// Build hook path
	hookPath := filepath.Join(hooksDir, "post-receive")

	// Hook content
	hookContent := `#!/bin/sh
# Gitolite-Golang mirror post-receive hook
# This hook is automatically generated

# Repository information
repo_name="$GL_REPO"

# Execute the original post-receive hook if it exists
if [ -x "$GL_HOOKS_DIR/post-receive.secondary" ]; then
  "$GL_HOOKS_DIR/post-receive.secondary"
fi

# Trigger mirror push
echo "Triggering mirror push for $repo_name"
exit 0
`

	// Create hook file
	return os.WriteFile(hookPath, []byte(hookContent), 0755)
}