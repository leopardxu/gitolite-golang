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

// sanitizeRepoName removes potentially dangerous characters from repository names
// to prevent command injection and other security issues
func sanitizeRepoName(repo string) string {
	// Remove any characters that could be used for command injection
	dangerousChars := []string{"'", "`", ";", "&", "|", ">", "<", "$", "(", ")", "[", "]", "{", "}", "\\"}
	result := repo
	
	for _, char := range dangerousChars {
		result = strings.ReplaceAll(result, char, "")
	}
	
	// Also remove any potential path traversal sequences
	result = strings.ReplaceAll(result, "..", "")
	
	return result
}
