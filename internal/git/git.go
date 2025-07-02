package git

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"
	"gitolite-golang/internal/validator"
)

// RefUpdate represents Git reference update information
type RefUpdate struct {
	RefName string // Reference name
	OldHash string // Old hash value
	NewHash string // New hash value
}

// ExecuteGitCommand executes Git commands with enhanced security validation
func ExecuteGitCommand(verb, repo, repoBase string) error {
	// Process repository path
	// Ensure repo doesn't contain .git suffix, as we'll add it later
	repo = strings.TrimSuffix(repo, ".git")
	
	// Validate repository name to prevent command injection
	if err := validator.ValidateRepoName(repo); err != nil {
		return fmt.Errorf("invalid repository name: %w", err)
	}
	
	// If it's a relative path, add repoBase prefix
	repoPath := filepath.Join(repoBase, repo+".git")

	// Handle repository initialization command
	if verb == "init" {
		// Create repository directory
		if err := os.MkdirAll(repoPath, 0755); err != nil {
			return fmt.Errorf("failed to create repository directory: %v", err)
		}

		// Initialize bare repository
		cmd := exec.Command("git", "init", "--bare")
		cmd.Dir = repoPath
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to initialize repository: %v, output: %s", err, output)
		}

		// Set default branch to stable
		cmd = exec.Command("git", "symbolic-ref", "HEAD", "refs/heads/stable")
		cmd.Dir = repoPath
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set default branch: %v, output: %s", err, output)
		}

		return nil
	}
	
	// Validate repository path using the validator
	validatedPath, err := validator.ValidatePath(repoBase, repo+".git")
	if err != nil {
		return fmt.Errorf("invalid repository path: %w", err)
	}
	repoPath = validatedPath

	// Log repository path information
	log.Log(log.INFO, fmt.Sprintf("Processing repository: %s, full path: %s", repo, repoPath))

	// Check if repository exists, if not and it's a push operation, initialize repository
	if verb == "git-receive-pack" {
		if err := ensureRepoExists(repoPath); err != nil {
			return fmt.Errorf("failed to ensure repository exists: %v", err)
		}
	} else if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("repository does not exist: %s", repo)
	}

	// Build Git command
	// Use repository path instead of repository name to ensure support for subdirectory structure
	log.Log(log.INFO, fmt.Sprintf("Executing Git command: %s on repository: %s", verb, repoPath))
	
	// Use a more secure approach to execute git commands
	var cmd *exec.Cmd
	switch verb {
	case "git-upload-pack":
		cmd = exec.Command("git", "upload-pack", repoPath)
	case "git-receive-pack":
		cmd = exec.Command("git", "receive-pack", repoPath)
	case "git-upload-archive":
		cmd = exec.Command("git", "upload-archive", repoPath)
	default:
		return fmt.Errorf("unsupported git command: %s", verb)
	}
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// ensureRepoExists ensures repository exists, initializes if not
func ensureRepoExists(repoPath string) error {
	// Check if repository already exists
	if _, err := os.Stat(repoPath); err == nil {
		return nil // Repository already exists
	}

	// Create repository directory
	if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
		return fmt.Errorf("failed to create repository directory: %v", err)
	}

	// Initialize bare repository
	cmd := exec.Command("git", "init", "--bare", repoPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to initialize repository: %v", err)
	}

	log.Log(log.INFO, fmt.Sprintf("Successfully initialized new repository: %s", repoPath))
	return nil
}

func InitBareRepository(repoPath string) error {
	// Fix: Execute command directly in the repository path
	cmd := exec.Command("git", "init", "--bare")
	cmd.Dir = repoPath // Instead of filepath.Dir(repoPath)
	return cmd.Run()
}

// SyncRepository performs repository synchronization
func SyncRepository(repoPath string, gerritRemoteURL string, repoBase string) error {
	// Get repository name
	log.Log(log.INFO, fmt.Sprintf("Starting full synchronization for repository %s", repoPath))

	// Check if gerrit remote repository already exists
	checkCmd := exec.Command("git", "remote")
	checkCmd.Dir = repoPath
	var out bytes.Buffer
	checkCmd.Stdout = &out
	if err := checkCmd.Run(); err != nil {
		log.Log(log.WARN, fmt.Sprintf("Failed to check remote repositories: %v", err))
	} else {
		// Check if output contains gerrit
		hasGerrit := false
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "gerrit" {
				hasGerrit = true
				break
			}
		}

		// If gerrit remote repository doesn't exist, add it
		if !hasGerrit {
			log.Log(log.INFO, fmt.Sprintf("Adding gerrit remote repository for %s", repoPath))
			// Sanitize the repository path to prevent command injection
			sanitizedRepoPath := strings.ReplaceAll(strings.TrimPrefix(repoPath, repoBase), "'", "")
			remoteURL := fmt.Sprintf("%s%s", gerritRemoteURL, sanitizedRepoPath)
			addCmd := exec.Command("git", "remote", "add", "gerrit", remoteURL)
			addCmd.Dir = repoPath
			if err := addCmd.Run(); err != nil {
				log.Log(log.ERROR, fmt.Sprintf("Failed to add gerrit remote repository: %v", err))
				// Continue execution, don't return error
			} else {
				log.Log(log.INFO, fmt.Sprintf("Successfully added remote repository: %s", remoteURL))
			}
		}
	}

	// Perform remote update
	cmd := exec.Command("git", "fetch", "gerrit", "--tags", "+refs/heads/*:refs/heads/*")
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute git fetch: %w", err)
	}

	cmd = exec.Command("git", "gc")
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute git gc: %w", err)
	}

	return nil
}

// GetUpdatedRefs gets recently updated references in the repository
func GetUpdatedRefs(repoPath string) ([]RefUpdate, error) {
	var out bytes.Buffer

	// Get all current references
	showRefCmd := exec.Command("git", "show-ref")
	showRefCmd.Dir = repoPath
	showRefCmd.Stdout = &out

	if err := showRefCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute git show-ref: %w", err)
	}

	currentRefs := make(map[string]string)
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			hash := parts[0]
			refName := parts[1]
			currentRefs[refName] = hash
		}
	}

	// Get recent reflog
	out.Reset()
	reflogCmd := exec.Command("git", "reflog", "--all", "--format=%H %gd %gs", "-n", "20")
	reflogCmd.Dir = repoPath
	reflogCmd.Stdout = &out

	if err := reflogCmd.Run(); err != nil {
		// If reflog command fails, it might be a new repository, return empty result
		return []RefUpdate{}, nil
	}

	// Parse reflog output, extract reference update information
	var updates []RefUpdate
	processedRefs := make(map[string]bool)

	scanner = bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: <hash> <refname> <message>
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}

		newHash := parts[0]
		refNameRaw := parts[1]
		message := parts[2]

		// Extract actual reference name from reflog reference name
		// Example: refs/heads/master@{0} -> refs/heads/master
		refName := strings.Split(refNameRaw, "@")[0]

		// Avoid processing duplicate references
		if processedRefs[refName] {
			continue
		}

		// Try to extract old hash value from message
		// Format is usually: "update by push" or "commit: <message>"
		oldHash := ""
		if strings.Contains(message, "update by push") || strings.Contains(message, "commit:") {
			// Get hash of previous reference
			oldHashCmd := exec.Command("git", "rev-parse", refName+"@{1}")
			oldHashCmd.Dir = repoPath
			oldHashBytes, err := oldHashCmd.Output()
			if err == nil {
				oldHash = strings.TrimSpace(string(oldHashBytes))
			}
		}

		// If unable to get old hash from reflog, use empty hash
		if oldHash == "" {
			oldHash = "0000000000000000000000000000000000000000"
		}

		// Mark this reference as processed
		processedRefs[refName] = true

		// Add to update list
		updates = append(updates, RefUpdate{
			RefName: refName,
			OldHash: oldHash,
			NewHash: newHash,
		})
	}

	// If no updates found, return empty list
	if len(updates) == 0 {
		return []RefUpdate{}, nil
	}

	return updates, nil
}
