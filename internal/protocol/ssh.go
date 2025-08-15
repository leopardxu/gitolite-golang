package protocol

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// ParseSSHCommand parses SSH requests
func ParseSSHCommand(cmd string) (verb, repo string, err error) {
	log.Printf("[DEBUG] Starting to parse SSH command: %s", cmd)

	if cmd == "" {
		log.Printf("[ERROR] SSH_ORIGINAL_COMMAND environment variable not set")
		return "", "", fmt.Errorf("SSH_ORIGINAL_COMMAND environment variable not set")
	}

	// Handle Gerrit replication commands with embedded Git operations
	if strings.Contains(cmd, "gerrit-replication") {
		return parseGerritReplicationCommand(cmd)
	}

	// Handle special commands, such as repository creation commands
	log.Printf("[INFO] cmd: %s ", cmd)
	if strings.Contains(cmd, "mkdir -p") && strings.Contains(cmd, "git init --bare") {
		log.Printf("[DEBUG] Repository creation command detected")
		// This is a repository creation command, extract the repository path
		repoPathStart := strings.Index(cmd, "'")
		repoPathEnd := strings.Index(cmd[repoPathStart+1:], "'")
		log.Printf("[DEBUG] Repository path quote positions: start=%d, end=%d", repoPathStart, repoPathEnd)

		if repoPathStart >= 0 && repoPathEnd >= 0 {
			repoPath := cmd[repoPathStart+1 : repoPathStart+1+repoPathEnd]
			log.Printf("[DEBUG] Extracted repository path: %s", repoPath)

			// Modification: Use the full path as the repository name, not just the last part
			repoName := repoPath

			// If the path ends with .git, remove it
			if strings.HasSuffix(repoName, ".git") {
				repoName = repoName[:len(repoName)-4]
				log.Printf("[DEBUG] Repository path after removing .git suffix: %s", repoName)
			}

			// Sanitize repository name to prevent command injection
			repoName = sanitizeRepoName(repoName)

			log.Printf("[INFO] Parse result: verb=init, repo=%s", repoName)
			return "init", repoName, nil
		}
		log.Printf("[ERROR] Unable to extract repository path from command")
	}

	// 禁止执行单独的 mkdir 命令，但允许仓库创建命令中的 mkdir
	if strings.HasPrefix(cmd, "mkdir ") && !strings.Contains(cmd, "git init --bare") {
		return "", "", fmt.Errorf("direct execution of mkdir command is not supported, please use git-receive-pack or git-upload-pack command")
	}

	// Original git command parsing logic
	log.Printf("[DEBUG] Using regex to parse git command")
	parts := strings.Split(cmd, " ")
	log.Printf("[DEBUG] Command split result: %v", parts)

	if len(parts) < 2 {
		log.Printf("[ERROR] Invalid SSH command: %s", cmd)
		return "", "", fmt.Errorf("invalid SSH command: %s", cmd)
	}

	re := regexp.MustCompile(`^(git-upload-pack|git-receive-pack|git-upload-archive) '?(.*?)'?$`)
	matches := re.FindStringSubmatch(cmd)
	log.Printf("[DEBUG] Regex match result: %v", matches)

	if len(matches) != 3 {
		log.Printf("[ERROR] Invalid SSH command: %s", cmd)
		return "", "", fmt.Errorf("invalid SSH command: %s", cmd)
	}

	// Process repository path
	// If it's a simplified path starting with /, remove the leading /
	repoPath := matches[2]
	repoPath = sanitizeRepoName(repoPath)

	if strings.HasPrefix(repoPath, "/") {
		repoPath = strings.TrimPrefix(repoPath, "/")
		log.Printf("[INFO] Simplified path format detected, converted to relative path: %s", repoPath)
	}

	log.Printf("[INFO] Parse result: verb=%s, repo=%s", matches[1], repoPath)
	return matches[1], repoPath, nil
}

// parseGerritReplicationCommand parses Gerrit replication commands to extract Git operation and repository
func parseGerritReplicationCommand(cmd string) (verb, repo string, err error) {
	log.Printf("[DEBUG] Parsing Gerrit replication command: %s", cmd)

	// Gerrit replication commands typically contain git-receive-pack or git-upload-pack
	if strings.Contains(cmd, "git-receive-pack") {
		// Extract repository from git-receive-pack command
		if repo, err := extractRepoFromGitCommand(cmd, "git-receive-pack"); err == nil {
			log.Printf("[INFO] Gerrit replication git-receive-pack for repo: %s", repo)
			return "gerrit-replication", repo, nil
		}
	} else if strings.Contains(cmd, "git-upload-pack") {
		// Extract repository from git-upload-pack command
		if repo, err := extractRepoFromGitCommand(cmd, "git-upload-pack"); err == nil {
			log.Printf("[INFO] Gerrit replication git-upload-pack for repo: %s", repo)
			return "gerrit-replication", repo, nil
		}
	} else if strings.Contains(cmd, "git-upload-archive") {
		// Extract repository from git-upload-archive command
		if repo, err := extractRepoFromGitCommand(cmd, "git-upload-archive"); err == nil {
			log.Printf("[INFO] Gerrit replication git-upload-archive for repo: %s", repo)
			return "gerrit-replication", repo, nil
		}
	}

	log.Printf("[ERROR] Unable to parse Gerrit replication command: %s", cmd)
	return "", "", fmt.Errorf("invalid Gerrit replication command: %s", cmd)
}

// extractRepoFromGitCommand extracts repository name from Git commands
func extractRepoFromGitCommand(cmd, gitCmd string) (string, error) {
	// Pattern to match git commands with repository path
	pattern := fmt.Sprintf(`%s\s+'([^']+)'`, regexp.QuoteMeta(gitCmd))
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(cmd)

	if len(matches) >= 2 {
		repo := matches[1]
		// Remove .git suffix if present
		if strings.HasSuffix(repo, ".git") {
			repo = repo[:len(repo)-4]
		}
		return sanitizeRepoName(repo), nil
	}

	// Try alternative pattern without quotes
	pattern = fmt.Sprintf(`%s\s+([^\s]+)`, regexp.QuoteMeta(gitCmd))
	re = regexp.MustCompile(pattern)
	matches = re.FindStringSubmatch(cmd)

	if len(matches) >= 2 {
		repo := matches[1]
		// Remove .git suffix if present
		if strings.HasSuffix(repo, ".git") {
			repo = repo[:len(repo)-4]
		}
		return sanitizeRepoName(repo), nil
	}

	return "", fmt.Errorf("unable to extract repository from command: %s", cmd)
}

// sanitizeRepoName removes potentially dangerous characters from repository names
// to prevent command injection and other security issues
func sanitizeRepoName(repo string) string {
	// Remove potentially dangerous characters
	repo = regexp.MustCompile(`[^a-zA-Z0-9/_.-]`).ReplaceAllString(repo, "")

	// Remove leading and trailing slashes
	repo = strings.Trim(repo, "/")

	// Prevent empty repository names
	if repo == "" {
		repo = "default"
	}

	return repo
}
