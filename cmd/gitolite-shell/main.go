package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	sync "sync" // Standard library sync package

	"gitolite-golang/internal/audit"
	"gitolite-golang/internal/config"
	"gitolite-golang/internal/gerrit"
	"gitolite-golang/internal/git"
	"gitolite-golang/internal/log"
	"gitolite-golang/internal/mirror"
	intsync "gitolite-golang/internal/sync" // Internal sync package, using alias to avoid conflict
)

func main() {
	// Parse command line arguments
	syncMode := flag.Bool("sync", false, "Only run key synchronization task")
	daemonMode := flag.Bool("daemon", false, "Run synchronization task in daemon mode")
	configPath := flag.String("config", "/home/cixtech/.gitolite/config.yaml", "Configuration file path")
	flag.Parse()

	// Get remaining arguments (user name if provided)
	args := flag.Args()
	var glUser string
	if len(args) > 0 {
		glUser = args[0]
	}

	// Initialize configuration and logging
	cfg, err := initConfigAndLogging(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Process based on running mode
	switch {
	case *syncMode:
		if err := runSyncMode(cfg); err != nil {
			log.Log(log.ERROR, err.Error())
			os.Exit(1)
		}
	case *daemonMode:
		runDaemonMode(cfg)
	default:
		if err := runNormalMode(cfg, glUser); err != nil {
			log.Log(log.ERROR, err.Error())
			os.Exit(1)
		}
	}
}

// Initialize configuration and logging
func initConfigAndLogging(configPath string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Set log level
	logLevel := getLogLevel(cfg.Log.Level)

	// Ensure log directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.Log.Path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Initialize logging system with complete log configuration
	logConfig := log.LogConfig{
		Path:     cfg.Log.Path,
		Level:    logLevel,
		Rotation: cfg.Log.Rotation,
		Compress: cfg.Log.Compress,
		MaxAge:   cfg.Log.MaxAge,
	}

	if err := log.InitWithConfig(logConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize logging: %w", err)
	}

	log.Log(log.INFO, "Gitolite-Golang started successfully")
	return cfg, nil
}

// Get log level
func getLogLevel(level string) log.LogLevel {
	switch level {
	case "WARN":
		return log.WARN
	case "ERROR":
		return log.ERROR
	default:
		return log.INFO
	}
}

// Sync mode processing
func runSyncMode(cfg *config.Config) error {
	keys, err := intsync.FetchGerritSSHKeys(cfg.GerritURL, cfg.GerritUser, cfg.GerritAPIToken)
	if err != nil {
		return fmt.Errorf("failed to get Gerrit SSH keys: %w (URL: %s, User: %s)",
			err, cfg.GerritURL, cfg.GerritUser)
	}

	gitoliteKeys := intsync.ConvertToGitoliteFormat(keys)
	if err := intsync.WriteAuthorizedKeys(gitoliteKeys, cfg.AuthorizedKeys); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w (Path: %s)",
			err, cfg.AuthorizedKeys)
	}

	log.Log(log.INFO, "Successfully synchronized SSH keys from Gerrit")
	return nil
}

// Daemon mode processing
func runDaemonMode(cfg *config.Config) {
	done := make(chan bool)

	// Start SSH key synchronization task
	intsync.StartSyncTask(cfg.GerritURL, cfg.GerritUser, cfg.GerritAPIToken, cfg.AuthorizedKeys)

	// Start mirror scheduler if mirroring is enabled
	if cfg.Mirror.Enabled && len(cfg.Mirror.Targets) > 0 {
		schedule := cfg.Mirror.Schedule
		if schedule == "" {
			schedule = "@hourly" // Default to hourly if not specified
		}
		log.Log(log.INFO, fmt.Sprintf("Starting mirror scheduler in daemon mode with schedule: %s", schedule))
		mirror.StartMirrorScheduler(cfg.RepoBase, mirror.MirrorConfig{
			Enabled:  cfg.Mirror.Enabled,
			Targets:  cfg.Mirror.Targets,
			Schedule: cfg.Mirror.Schedule,
		}, schedule)
	}

	<-done
}

// Normal mode processing
func runNormalMode(cfg *config.Config, glUser string) error {
	// Initialize audit logger
	auditLogger := audit.NewAuditLogger(cfg.Audit.LogPath, cfg.Audit.Enabled)

	// 1. Parse SSH original command
	sshCommand := os.Getenv("SSH_ORIGINAL_COMMAND")
	if sshCommand == "" {
		log.Log(log.WARN, "SSH_ORIGINAL_COMMAND environment variable not set, user may be directly logging in via SSH")
		// Provide friendly message instead of returning an error
		fmt.Println("Welcome to Gitolite-Golang, please access repositories through Git commands.")
		return nil
	}

	log.Log(log.INFO, fmt.Sprintf("Processing SSH command: %s", sshCommand))
	// Log repository path information
	log.Log(log.INFO, fmt.Sprintf("Repository base path: %s", cfg.RepoBase))
	// Build complete repository path for logging
	// fullRepoPath := filepath.Join(cfg.RepoBase, repo+".git")
	// log.Log(log.INFO, fmt.Sprintf("Complete repository path: %s", fullRepoPath))

	// Improved command parsing logic to handle options
	parts := strings.Fields(sshCommand)
	if len(parts) < 1 {
		return fmt.Errorf("invalid SSH command format")
	}

	verb := parts[0]

	// Ensure there are enough parameters to get the repository name
	if len(parts) < 2 {
		return fmt.Errorf("command missing repository parameter")
	}

	repo := strings.Trim(strings.Join(parts[1:], " "), "'\"")

	// Handle potential absolute path issues
	repo = strings.TrimPrefix(repo, "/")
	// Handle potential absolute path issues, ensure it doesn't contain repo_base prefix
	repo = strings.TrimPrefix(repo, cfg.RepoBase)
	// Log the processed repository path
	log.Log(log.INFO, fmt.Sprintf("Processed repository path: %s", repo))

	// Get user information, prioritize command line argument, then GL_USER, then SSH_USER or USER
	var user string
	if glUser != "" {
		user = glUser
		log.Log(log.INFO, fmt.Sprintf("Using user from command line argument: %s", user))
	} else {
		user = os.Getenv("GL_USER")
		if user == "" {
			user = os.Getenv("SSH_USER")
			if user == "" {
				user = os.Getenv("USER")
				if user == "" {
					return fmt.Errorf("unable to determine user identity, no command line argument provided and GL_USER, SSH_USER and USER environment variables are all not set")
				}
			}
			log.Log(log.WARN, fmt.Sprintf("GL_USER not set, using fallback user: %s", user))
		}
	}

	// Collect access information for audit
	accessInfo := audit.CollectAccessInfo(user, repo, audit.GetOperationType(verb), sshCommand)

	// 2. Process special commands
	var err error
	switch verb {
	case "init":
		err = handleRepoInit(cfg, user, repo)
	case "git-upload-pack", "git-receive-pack":
		// git-receive-pack command handles both normal commits and tag operations
		err = handleGitOperation(cfg, user, repo, verb)
	case "git-upload-archive":
		err = handleGitArchive(cfg, user, repo)
	case "info":
		err = handleInfo(cfg, user, repo)
	case "access":
		err = handleAccess(cfg, user, repo)
	case "git-config":
		err = handleGitConfig(cfg, user, repo)
	case "perms":
		err = handlePerms(cfg, user, repo)
	case "gerrit-replication":
		err = handleGerritReplication(cfg, user, repo)
	default:
		// Check if it's a mkdir command, provide more specific error message
		if strings.Contains(verb, "mkdir") {
			log.Log(log.ERROR, fmt.Sprintf("Unsupported Git command: %s, should use repo_base as the base path", verb))
			err = fmt.Errorf("direct execution of mkdir command is not supported, please use git-receive-pack or git-upload-pack command")
		} else {
			err = fmt.Errorf("unsupported Git command: %s", verb)
		}
	}

	// Update access result and log audit information
	if err != nil {
		accessInfo.UpdateResult(false, err.Error())
	} else {
		accessInfo.UpdateResult(true, "")
	}

	// Log access information if console output is enabled
	if cfg.Audit.ConsoleOut {
		auditLogger.LogAccess(accessInfo)
	}

	return err
}

// Handle Gerrit replication synchronization task
func handleGerritReplication(cfg *config.Config, user, repo string) error {
	// Ensure repository name format is correct
	repo = strings.TrimPrefix(repo, "/")
	// Ensure it doesn't contain repo_base prefix
	repo = strings.TrimPrefix(repo, cfg.RepoBase)
	// Log the repository path being processed
	log.Log(log.INFO, fmt.Sprintf("Processing Gerrit replication repository path: %s", repo))
	// Remove possible .git suffix, will be added back later
	repo = strings.TrimSuffix(repo, ".git")

	// Record SSH connection information
	remoteAddr := os.Getenv("SSH_CLIENT")
	pid := os.Getpid()
	log.Log(log.INFO, fmt.Sprintf("%d ssh ARGV=server-%s SOC=git-receive-pack '%s' FROM=%s",
		pid, user, repo, remoteAddr))

	// Record mirror pre_git information
	log.Log(log.INFO, fmt.Sprintf("%d mirror,pre_git,%s,user=,sender=%s,mode=copy",
		pid, repo, user))

	// Check if it's a replication dedicated account
	if user != "gerrit-replication" && user != "git" {
		log.Log(log.WARN, fmt.Sprintf("Unauthorized user attempting to execute replication operation: %s", user))
		return fmt.Errorf("Only gerrit-replication user can perform this operation")
	}

	// Get repository path
	repoPath := filepath.Join(cfg.RepoBase, repo+".git")

	// Log the git command being executed
	log.Log(log.INFO, fmt.Sprintf("%d system,git,shell,-c,git-receive-pack '%s'",
		pid, repoPath))

	// Check if repository exists
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		log.Log(log.INFO, fmt.Sprintf("Repository does not exist, creating automatically: %s", repo))
		if err := handleRepoInit(cfg, user, repo); err != nil {
			return err
		}
	}

	// Execute synchronization operation, passing the Gerrit remote URL from configuration:
	if err := git.SyncRepository(repoPath, cfg.GerritRemoteURL, cfg.RepoBase); err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Repository synchronization failed: %s, error: %v", repo, err))
		return fmt.Errorf("Repository synchronization failed: %w", err)
	}

	// Record reference update information
	refs, err := git.GetUpdatedRefs(repoPath)
	if err == nil && len(refs) > 0 {
		for _, ref := range refs {
			log.Log(log.INFO, fmt.Sprintf("%d update %s (git) bypass %s %s %s",
				pid, repoPath, ref.RefName, ref.OldHash, ref.NewHash))
		}
	}

	// Record post_git information
	hostname, _ := os.Hostname()
	log.Log(log.INFO, fmt.Sprintf("%d post_git() on %s", pid, hostname))
	log.Log(log.INFO, fmt.Sprintf("%d mirror,post_git,%s,user=,sender=%s,mode=copy",
		pid, repo, user))

	// Record end marker
	log.Log(log.INFO, fmt.Sprintf("%d END", pid))

	// Execute hook scripts
	runHooks(cfg, "post-receive", repo, user)

	return nil
}

// Handle repository initialization
func handleRepoInit(cfg *config.Config, user, repo string) error {
	// Ensure repository path format is correct
	repo = strings.TrimPrefix(repo, "/")
	// Ensure it doesn't contain repo_base prefix
	repo = strings.TrimPrefix(repo, cfg.RepoBase)
	// Log the repository path being processed
	log.Log(log.INFO, fmt.Sprintf("Initializing repository path: %s", repo))
	// Remove possible .git suffix
	repo = strings.TrimSuffix(repo, ".git")
	// Build complete repository path
	repoPath := filepath.Join(cfg.RepoBase, repo+".git")

	// Check if repository already exists
	if _, err := os.Stat(repoPath); err == nil {
		log.Log(log.INFO, fmt.Sprintf("Repository already exists, skipping initialization: %s (full path: %s)", repo, repoPath))
		return nil
	}

	// Create repository directory
	log.Log(log.INFO, fmt.Sprintf("Creating repository directory: %s", repoPath))
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		return fmt.Errorf("Failed to create repository directory: %w (path: %s)", err, repoPath)
	}

	// Execute git init --bare in the repository directory
	cmd := exec.Command("git", "init", "--bare")
	cmd.Dir = repoPath // Set working directory to repository path
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to initialize bare repository: %v, output: %s", err, string(output)))
		return fmt.Errorf("Failed to initialize bare repository: %w", err)
	}

	// Set default branch (if needed)
	branchName := "master" // Default branch name
	// Check if the command contains branch information
	if strings.Contains(os.Getenv("SSH_ORIGINAL_COMMAND"), "git symbolic-ref HEAD") {
		// Extract branch name from original command
		cmdStr := os.Getenv("SSH_ORIGINAL_COMMAND")
		refParts := strings.Split(cmdStr, "'refs/heads/")
		if len(refParts) >= 2 {
			branchEnd := strings.Index(refParts[1], "'")
			if branchEnd > 0 {
				branchName = refParts[1][:branchEnd]
			}
		}
	}

	// Set default branch
	if branchName != "master" {
		refCmd := exec.Command("git", "symbolic-ref", "HEAD", fmt.Sprintf("refs/heads/%s", branchName))
		refCmd.Dir = repoPath
		refOutput, refErr := refCmd.CombinedOutput()
		if refErr != nil {
			log.Log(log.WARN, fmt.Sprintf("Failed to set default branch: %v, output: %s", refErr, string(refOutput)))
			// Don't return error, as the main operation has already succeeded
		} else {
			log.Log(log.INFO, fmt.Sprintf("Successfully set default branch to: %s", branchName))
		}
	}

	log.Log(log.INFO, fmt.Sprintf("User %s successfully created repository %s (full path: %s)", user, repo, repoPath))

	// Perform full synchronization after repository creation
	log.Log(log.INFO, fmt.Sprintf("Starting full synchronization for new repository %s", repo))
	if err := git.SyncRepository(repoPath, cfg.GerritRemoteURL, cfg.RepoBase); err != nil {
		log.Log(log.WARN, fmt.Sprintf("New repository %s synchronization failed: %v", repo, err))
		// We only log a warning here, not returning an error, because the repository has been successfully created
	} else {
		log.Log(log.INFO, fmt.Sprintf("New repository %s synchronized successfully", repo))
	}

	// Execute hook scripts
	runHooks(cfg, "post-create", repo, user)

	return nil
}

// Handle Git operations
func handleGitOperation(cfg *config.Config, user, repo, verb string) error {
	// Ensure repository name format is correct
	repo = strings.TrimPrefix(repo, "/")
	// Ensure it doesn't contain repo_base prefix
	repo = strings.TrimPrefix(repo, cfg.RepoBase)
	// Log the repository path being processed
	log.Log(log.INFO, fmt.Sprintf("Processing Git operation repository path: %s", repo))
	// Remove possible .git suffix
	repoBase := strings.TrimSuffix(repo, ".git")

	// Only perform permission check for non-synchronization users
	if user != "gerrit-replication" && user != "git" {
		// Improved error handling, capture and log detailed API call errors
		allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoBase,
			cfg.GerritUser, cfg.GerritAPIToken)
		if err != nil {
			// Log detailed error information to help diagnose problems
			log.Log(log.ERROR, fmt.Sprintf("Gerrit API call failed: %v (URL: %s, User: %s, Repo: %s)",
				err, cfg.GerritURL, user, repoBase))

			// Check if the error contains specific strings, possibly a command line parameter error
			errStr := err.Error()
			if strings.Contains(errStr, "--account") {
				log.Log(log.WARN, "Detected possible Gerrit API parameter error, please check configuration")
				return fmt.Errorf("Gerrit API configuration error, please contact administrator")
			}

			return fmt.Errorf("Failed to check access permission: %w", err)
		}
		if !allowed {
			return fmt.Errorf("User %s has no permission to access repository %s", user, repoBase)
		}
	} else {
		log.Log(log.INFO, fmt.Sprintf("Synchronization user %s operating repository %s, skipping permission check", user, repoBase))
	}

	// Check if repository exists
	repoPath := filepath.Join(cfg.RepoBase, repoBase+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		// If it's a push operation and the repository doesn't exist, create the repository
		if verb == "git-receive-pack" {
			log.Log(log.INFO, fmt.Sprintf("Repository does not exist, creating automatically: %s", repoBase))
			if err := handleRepoInit(cfg, user, repoBase); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Repository does not exist: %s", repoPath)
		}
	}

	// Execute pre-receive hook (only for push operations)
	if verb == "git-receive-pack" {
		if err := runHooks(cfg, "pre-receive", repoBase, user); err != nil {
			return fmt.Errorf("pre-receive hook execution failed: %w", err)
		}
	}

	// Execute Git command, passing repository name without .git suffix
	err := git.ExecuteGitCommand(verb, repoBase, cfg.RepoBase)

	// If it's a push operation, check if there are tag updates
	if verb == "git-receive-pack" && err == nil {
		// Record reference update information, with special attention to tags
		refs, refErr := git.GetUpdatedRefs(repoPath)
		if refErr == nil && len(refs) > 0 {
			pid := os.Getpid()
			for _, ref := range refs {
				// Record all reference updates, especially mark tag operations
				if strings.HasPrefix(ref.RefName, "refs/tags/") {
					log.Log(log.INFO, fmt.Sprintf("Detected tag operation: %s", ref.RefName))
				}
				log.Log(log.INFO, fmt.Sprintf("%d update %s (git) bypass %s %s %s",
					pid, repoPath, ref.RefName, ref.OldHash, ref.NewHash))
			}
		}

		// Execute post-receive hook
		if err := runHooks(cfg, "post-receive", repoBase, user); err != nil {
			log.Log(log.WARN, fmt.Sprintf("post-receive hook execution failed: %v", err))
			// Don't return error, as the main operation has already succeeded
		}
	}

	return err
}

// Handle Git archive operations
func handleGitArchive(cfg *config.Config, user, repo string) error {
	// Ensure repository name format is correct
	repo = strings.TrimPrefix(repo, "/")
	// Ensure it doesn't contain repo_base prefix
	repo = strings.TrimPrefix(repo, cfg.RepoBase)
	// Log the repository path being processed
	log.Log(log.INFO, fmt.Sprintf("Processing Git archive operation repository path: %s", repo))
	// Remove possible .git suffix
	repoBase := strings.TrimSuffix(repo, ".git")

	// Only perform permission check for non-synchronization users
	if user != "gerrit-replication" && user != "git" {
		allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoBase,
			cfg.GerritUser, cfg.GerritAPIToken)
		if err != nil {
			return fmt.Errorf("Failed to check archive permission: %w", err)
		}
		if !allowed {
			return fmt.Errorf("User %s has no permission to archive repository %s", user, repoBase)
		}
	} else {
		log.Log(log.INFO, fmt.Sprintf("Synchronization user %s archiving repository %s, skipping permission check", user, repoBase))
	}

	// Check if repository exists
	repoPath := filepath.Join(cfg.RepoBase, repoBase+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("Repository does not exist: %s", repoPath)
	}

	return git.ExecuteGitCommand("git-upload-archive", repoBase, cfg.RepoBase)
}

// Handle info command, display repository information accessible to the user
func handleInfo(cfg *config.Config, user, repo string) error {
	// Log the execution of info command
	log.Log(log.INFO, fmt.Sprintf("User %s executing info command", user))

	// If a specific repository is specified, only display information for that repository
	if repo != "" {
		repo = strings.TrimPrefix(repo, "/")
		repo = strings.TrimPrefix(repo, cfg.RepoBase)
		repo = strings.TrimSuffix(repo, ".git")

		// Check user's access permission for this repository
		allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repo,
			cfg.GerritUser, cfg.GerritAPIToken)
		if err != nil {
			return fmt.Errorf("Failed to check repository access permission: %w", err)
		}

		// Build repository path
		repoPath := filepath.Join(cfg.RepoBase, repo+".git")

		// Check if repository exists
		if _, err := os.Stat(repoPath); os.IsNotExist(err) {
			return fmt.Errorf("Repository does not exist: %s", repoPath)
		}

		// Display repository information
		fmt.Printf("Repository: %s\n", repo)
		fmt.Printf("Access permission: %v\n", allowed)

		// Get repository branch information
		cmd := exec.Command("git", "branch")
		cmd.Dir = repoPath
		branchOutput, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("Branches:\n%s\n", string(branchOutput))
		}

		return nil
	}

	// If no repository is specified, list all repositories accessible to the user
	// Traverse the repository directory
	repos, err := listRepositories(cfg.RepoBase)
	if err != nil {
		return fmt.Errorf("Failed to list repositories: %w", err)
	}

	// Create a concurrent pool to check permissions
	type repoAccess struct {
		repo    string
		allowed bool
	}

	// Use goroutine pool and channels to limit concurrency
	maxWorkers := 5
	jobs := make(chan string, len(repos))
	results := make(chan repoAccess, len(repos))
	wg := sync.WaitGroup{}

	// Start worker goroutines
	for w := 1; w <= maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range jobs {
				// Check user's access permission for the repository
				allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repo,
					cfg.GerritUser, cfg.GerritAPIToken)
				if err != nil {
					log.Log(log.WARN, fmt.Sprintf("Failed to check repository %s access permission: %v", repo, err))
					allowed = false
				}
				results <- repoAccess{repo: repo, allowed: allowed}
			}
		}()
	}

	// Send tasks
	for _, repo := range repos {
		jobs <- repo
	}
	close(jobs)

	// Wait for all work to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and display
	fmt.Printf("Repositories accessible to user %s:\n\n", user)
	accessCount := 0

	// Collect all results
	accessList := []repoAccess{}
	for result := range results {
		accessList = append(accessList, result)
	}

	// Sort by repository name
	sort.Slice(accessList, func(i, j int) bool {
		return accessList[i].repo < accessList[j].repo
	})

	// Display results
	for _, access := range accessList {
		if access.allowed {
			fmt.Printf("R W    %s\n", access.repo)
			accessCount++
		}
	}

	fmt.Printf("\nTotal of %d accessible repositories\n", accessCount)
	return nil
}

// Handle access command, check user's access permission for a specific repository
func handleAccess(cfg *config.Config, user, repo string) error {
	// Log the execution of access command
	log.Log(log.INFO, fmt.Sprintf("User %s executing access command", user))

	// Parse command parameters
	// Format: access <permission> <repository> <reference>
	// Example: access R repo refs/heads/master
	args := strings.Fields(os.Getenv("SSH_ORIGINAL_COMMAND"))
	if len(args) < 2 {
		return fmt.Errorf("Access command format error, correct format: access <permission> <repository> [<reference>]")
	}

	// Extract permission type and repository name
	permission := ""
	repoName := ""
	refName := ""

	// Skip the first parameter (access)
	if len(args) >= 3 {
		permission = args[1]
		repoName = args[2]
	}

	// If there's a reference name
	if len(args) >= 4 {
		refName = args[3]
	}

	// If repository name wasn't obtained from command line, use the passed repo parameter
	if repoName == "" && repo != "" {
		repoName = repo
	}

	// Ensure repository name format is correct
	repoName = strings.TrimPrefix(repoName, "/")
	repoName = strings.TrimPrefix(repoName, cfg.RepoBase)
	repoName = strings.TrimSuffix(repoName, ".git")

	// Check if repository exists
	repoPath := filepath.Join(cfg.RepoBase, repoName+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("Repository does not exist: %s", repoPath)
	}

	// Check user's access permission for this repository
	allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoName,
		cfg.GerritUser, cfg.GerritAPIToken)
	if err != nil {
		return fmt.Errorf("Failed to check repository access permission: %w", err)
	}

	// Display access permission results
	if allowed {
		// Return results based on requested permission type
		switch permission {
		case "R":
			// Read permission check
			fmt.Printf("User %s has read permission for repository %s\n", user, repoName)
			if refName != "" {
				fmt.Printf("Reference: %s\n", refName)
			}
		case "W":
			// Write permission check
			fmt.Printf("User %s has write permission for repository %s\n", user, repoName)
			if refName != "" {
				fmt.Printf("Reference: %s\n", refName)
			}
		default:
			// Default display all permissions
			fmt.Printf("User %s has read/write permission for repository %s\n", user, repoName)
			if refName != "" {
				fmt.Printf("Reference: %s\n", refName)
			}
		}
	} else {
		fmt.Printf("User %s has no access permission for repository %s\n", user, repoName)
		if refName != "" {
			fmt.Printf("Reference: %s\n", refName)
		}
	}

	return nil
}

// handleGitConfig handles the git-config command, managing Git configuration for repositories
func handleGitConfig(cfg *config.Config, user, repo string) error {
	// Log the execution of git-config command
	log.Log(log.INFO, fmt.Sprintf("User %s executing git-config command", user))

	// Parse command parameters
	// Format: git-config <repository> <operation> <config key> [<config value>]
	// Example: git-config repo get core.sharedRepository
	//          git-config repo set core.sharedRepository group
	args := strings.Fields(os.Getenv("SSH_ORIGINAL_COMMAND"))
	if len(args) < 4 {
		return fmt.Errorf("Git-config command format error, correct format: git-config <repository> <operation> <config key> [<config value>]")
	}

	// Extract parameters
	repoName := ""
	operation := ""
	configKey := ""
	configValue := ""

	// Skip the first parameter (git-config)
	if len(args) >= 4 {
		repoName = args[1]
		operation = args[2]
		configKey = args[3]
	}

	// If there's a config value
	if len(args) >= 5 {
		configValue = args[4]
	}

	// If repository name wasn't obtained from command line, use the passed repo parameter
	if repoName == "" && repo != "" {
		repoName = repo
	}

	// Ensure repository name format is correct
	repoName = strings.TrimPrefix(repoName, "/")
	repoName = strings.TrimPrefix(repoName, cfg.RepoBase)
	repoName = strings.TrimSuffix(repoName, ".git")

	// Check if repository exists
	repoPath := filepath.Join(cfg.RepoBase, repoName+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("Repository does not exist: %s", repoPath)
	}

	// Check user's access permission for this repository
	allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoName,
		cfg.GerritUser, cfg.GerritAPIToken)
	if err != nil {
		return fmt.Errorf("Failed to check repository access permission: %w", err)
	}

	// Only users with permission can operate
	if !allowed {
		return fmt.Errorf("User %s has no permission to operate repository %s configuration", user, repoName)
	}

	// Execute different operations based on operation type
	switch operation {
	case "get":
		// Get configuration value
		cmd := exec.Command("git", "config", "--get", configKey)
		cmd.Dir = repoPath
		output, err := cmd.CombinedOutput()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				// Configuration doesn't exist, return empty value
				fmt.Printf("Configuration %s does not exist\n", configKey)
				return nil
			}
			return fmt.Errorf("Failed to get configuration: %w, output: %s", err, string(output))
		}
		fmt.Printf("%s = %s", configKey, string(output))

	case "set":
		// Set configuration value
		if configValue == "" {
			return fmt.Errorf("Setting configuration requires providing a configuration value")
		}
		cmd := exec.Command("git", "config", configKey, configValue)
		cmd.Dir = repoPath
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to set configuration: %w, output: %s", err, string(output))
		}
		fmt.Printf("Successfully set %s = %s\n", configKey, configValue)

	case "unset":
		// Delete configuration
		cmd := exec.Command("git", "config", "--unset", configKey)
		cmd.Dir = repoPath
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to delete configuration: %w, output: %s", err, string(output))
		}
		fmt.Printf("Successfully deleted configuration %s\n", configKey)

	case "list":
		// List all configurations
		cmd := exec.Command("git", "config", "--list")
		cmd.Dir = repoPath
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to list configurations: %w, output: %s", err, string(output))
		}
		fmt.Printf("Repository %s configurations:\n%s", repoName, string(output))

	default:
		return fmt.Errorf("Unsupported operation: %s, supported operations: get, set, unset, list", operation)
	}

	return nil
}

// handlePerms handles the perms command, managing repository permissions
func handlePerms(cfg *config.Config, user, repo string) error {
	// Log the execution of perms command
	log.Log(log.INFO, fmt.Sprintf("User %s executing perms command", user))

	// Parse command parameters
	// Format: perms <repository> <operation> [<reference>] [<permission>]
	// Example: perms repo + refs/heads/master R
	//          perms repo - refs/heads/feature W
	//          perms repo list
	args := strings.Fields(os.Getenv("SSH_ORIGINAL_COMMAND"))
	if len(args) < 3 {
		return fmt.Errorf("Perms command format error, correct format: perms <repository> <operation> [<reference>] [<permission>]")
	}

	// Extract parameters
	repoName := ""
	operation := ""
	refName := ""
	permission := ""

	// Skip the first parameter (perms)
	if len(args) >= 3 {
		repoName = args[1]
		operation = args[2]
	}

	// If there's a reference name
	if len(args) >= 4 {
		refName = args[3]
	}

	// If there's a permission
	if len(args) >= 5 {
		permission = args[4]
	}

	// If repository name wasn't obtained from command line, use the passed repo parameter
	if repoName == "" && repo != "" {
		repoName = repo
	}

	// Ensure repository name format is correct
	repoName = strings.TrimPrefix(repoName, "/")
	repoName = strings.TrimPrefix(repoName, cfg.RepoBase)
	repoName = strings.TrimSuffix(repoName, ".git")

	// Check if repository exists
	repoPath := filepath.Join(cfg.RepoBase, repoName+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("Repository does not exist: %s", repoPath)
	}

	// Check user's access permission for this repository
	allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoName,
		cfg.GerritUser, cfg.GerritAPIToken)
	if err != nil {
		return fmt.Errorf("Failed to check repository access permission: %w", err)
	}

	// Only users with permission can operate
	if !allowed {
		return fmt.Errorf("User %s has no permission to operate repository %s permissions", user, repoName)
	}

	// Permission file path
	permsFile := filepath.Join(repoPath, "gl-perms")

	// Execute different operations based on operation type
	switch operation {
	case "list":
		// List all permissions
		if _, err := os.Stat(permsFile); os.IsNotExist(err) {
			fmt.Printf("Repository %s has no special permissions set\n", repoName)
			return nil
		}

		// Read permissions file
		permsData, err := os.ReadFile(permsFile)
		if err != nil {
			return fmt.Errorf("Failed to read permissions file: %w", err)
		}

		fmt.Printf("Repository %s permissions settings:\n%s\n", repoName, string(permsData))

	case "+":
		// Add permission
		if refName == "" || permission == "" {
			return fmt.Errorf("Adding permission requires providing reference and permission")
		}

		// Ensure permission value is valid
		if permission != "R" && permission != "W" && permission != "RW" && permission != "-" {
			return fmt.Errorf("Invalid permission value: %s, valid values: R, W, RW, -", permission)
		}

		// Read existing permissions
		var permsLines []string
		if _, err := os.Stat(permsFile); !os.IsNotExist(err) {
			permsData, err := os.ReadFile(permsFile)
			if err != nil {
				return fmt.Errorf("Failed to read permissions file: %w", err)
			}
			permsLines = strings.Split(string(permsData), "\n")
		}

		// Check if permission for this reference already exists
		found := false
		for i, line := range permsLines {
			if strings.HasPrefix(line, refName+" ") {
				// Update existing permission
				permsLines[i] = refName + " " + permission
				found = true
				break
			}
		}

		// If not exists, add new permission
		if !found {
			permsLines = append(permsLines, refName+" "+permission)
		}

		// Write permissions file
		permsData := strings.Join(permsLines, "\n")
		if err := os.WriteFile(permsFile, []byte(permsData), 0644); err != nil {
			return fmt.Errorf("Failed to write permissions file: %w", err)
		}

		fmt.Printf("Successfully added permission %s for reference %s in repository %s\n", permission, refName, repoName)

	case "-":
		// Remove permission
		if refName == "" {
			return fmt.Errorf("Removing permission requires providing reference")
		}

		// Check if permissions file exists
		if _, err := os.Stat(permsFile); os.IsNotExist(err) {
			fmt.Printf("Repository %s has no special permissions set\n", repoName)
			return nil
		}

		// Read existing permissions
		permsData, err := os.ReadFile(permsFile)
		if err != nil {
			return fmt.Errorf("Failed to read permissions file: %w", err)
		}
		permsLines := strings.Split(string(permsData), "\n")

		// Remove permission for specified reference
		newPermsLines := []string{}
		removed := false
		for _, line := range permsLines {
			if strings.HasPrefix(line, refName+" ") {
				removed = true
				continue
			}
			if line != "" {
				newPermsLines = append(newPermsLines, line)
			}
		}

		if !removed {
			fmt.Printf("Reference %s in repository %s has no special permissions set\n", refName, repoName)
			return nil
		}

		// Write permissions file
		newPermsData := strings.Join(newPermsLines, "\n")
		if err := os.WriteFile(permsFile, []byte(newPermsData), 0644); err != nil {
			return fmt.Errorf("Failed to write permissions file: %w", err)
		}

		fmt.Printf("Successfully removed permission for reference %s in repository %s\n", refName, repoName)

	default:
		return fmt.Errorf("Unknown operation type: %s, supported operations: list, +, -", operation)
	}

	return nil
}

// List all repositories in the repository directory
func listRepositories(repoBase string) ([]string, error) {
	var repos []string

	// Traverse the repository directory
	err := filepath.Walk(repoBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only process directories
		if !info.IsDir() {
			return nil
		}

		// Check if it's a Git repository (with .git suffix)
		if strings.HasSuffix(path, ".git") {
			// Extract relative path
			relPath, err := filepath.Rel(repoBase, path)
			if err != nil {
				return err
			}

			// Remove .git suffix
			repoName := strings.TrimSuffix(relPath, ".git")
			repos = append(repos, repoName)
		}

		return nil
	})

	return repos, err
}

// Execute hook scripts
func runHooks(cfg *config.Config, hookType, repo, user string) error {
	// Check if hook directory exists
	hooksDir := cfg.HooksDir
	if hooksDir == "" {
		hooksDir = "~/.gitolite/hooks"
	}

	// Build hook script path
	hookPath := filepath.Join(hooksDir, hookType)
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		// Hook script doesn't exist, skip execution
		log.Log(log.INFO, fmt.Sprintf("Hook script doesn't exist, skipping execution: %s", hookPath))

		// If this is a post-receive hook, check if we need to handle mirroring
		if hookType == "post-receive" && cfg.Mirror.Enabled {
			repoPath := filepath.Join(cfg.RepoBase, repo+".git")
			return handleMirrorPush(cfg, repoPath, repo)
		}

		return nil
	}

	// Set environment variables
	cmd := exec.Command(hookPath)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GL_REPO=%s", repo),
		fmt.Sprintf("GL_USER=%s", user),
		fmt.Sprintf("GL_HOOKS_DIR=%s", hooksDir),
	)

	// Execute hook script
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Hook script execution failed: %s, error: %v, output: %s",
			hookPath, err, string(output)))
		return fmt.Errorf("Hook script execution failed: %w", err)
	}

	log.Log(log.INFO, fmt.Sprintf("Hook script executed successfully: %s, output: %s",
		hookPath, string(output)))

	// If this is a post-receive hook, check if we need to handle mirroring
	if hookType == "post-receive" && cfg.Mirror.Enabled {
		repoPath := filepath.Join(cfg.RepoBase, repo+".git")
		if err := handleMirrorPush(cfg, repoPath, repo); err != nil {
			log.Log(log.WARN, fmt.Sprintf("Mirror push failed: %v", err))
			// Don't return error, as the main operation has already succeeded
		}
	}

	return nil
}

// Handle mirror push operation
func handleMirrorPush(cfg *config.Config, repoPath, repoName string) error {
	// If mirroring is not enabled, return immediately
	if !cfg.Mirror.Enabled || len(cfg.Mirror.Targets) == 0 {
		return nil
	}

	log.Log(log.INFO, fmt.Sprintf("Starting mirror push for repository %s", repoName))

	// Mirror the repository to all configured targets
	return mirror.MirrorRepository(repoPath, repoName, mirror.MirrorConfig{
		Enabled:  cfg.Mirror.Enabled,
		Targets:  cfg.Mirror.Targets,
		Schedule: cfg.Mirror.Schedule,
	}, true)
}
