package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/config"
	"gitolite-golang/internal/log"
	"gitolite-golang/internal/mirror"
)

func main() {
	// Parse command line arguments
	configPath := flag.String("config", "/home/git/.gitolite/config.yaml", "Configuration file path")
	repoName := flag.String("repo", "", "Repository name to mirror (without .git suffix)")
	allRepos := flag.Bool("all", false, "Mirror all repositories")
	async := flag.Bool("async", false, "Push asynchronously")
	target := flag.String("target", "", "Specific target to push to (by name)")
	flag.Parse()

	// Initialize configuration and logging
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Set log level
	logLevel := getLogLevel(cfg.Log.Level)

	// Initialize logging system
	logConfig := log.LogConfig{
		Path:     cfg.Log.Path,
		Level:    logLevel,
		Rotation: cfg.Log.Rotation,
		Compress: cfg.Log.Compress,
		MaxAge:   cfg.Log.MaxAge,
	}

	if err := log.InitWithConfig(logConfig); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logging: %v\n", err)
		os.Exit(1)
	}

	// Check if mirroring is enabled
	if !cfg.Mirror.Enabled || len(cfg.Mirror.Targets) == 0 {
		fmt.Println("Mirroring is not enabled or no targets configured")
		os.Exit(1)
	}

	// If a specific target is specified, filter the targets
	if *target != "" {
		var targetFound bool
		var filteredTargets []mirror.MirrorTarget

		for _, t := range cfg.Mirror.Targets {
			if t.Name == *target {
				filteredTargets = append(filteredTargets, t)
				targetFound = true
				break
			}
		}

		if !targetFound {
			fmt.Printf("Target '%s' not found in configuration\n", *target)
			os.Exit(1)
		}

		cfg.Mirror.Targets = filteredTargets
	}

	// Mirror repositories
	if *allRepos {
		// Mirror all repositories
		repos, err := listRepositories(cfg.RepoBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list repositories: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Mirroring %d repositories...\n", len(repos))

		for _, repo := range repos {
			repoPath := filepath.Join(cfg.RepoBase, repo+".git")
			fmt.Printf("Mirroring repository: %s\n", repo)

			if err := mirror.MirrorRepository(repoPath, repo, mirror.MirrorConfig{
				Enabled: cfg.Mirror.Enabled,
				Targets: cfg.Mirror.Targets,
			}, *async); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to mirror repository %s: %v\n", repo, err)
				// Continue with other repositories
			} else {
				fmt.Printf("Successfully mirrored repository: %s\n", repo)
			}
		}
	} else if *repoName != "" {
		// Mirror a specific repository
		repoPath := filepath.Join(cfg.RepoBase, *repoName+".git")

		// Check if repository exists
		if _, err := os.Stat(repoPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Repository does not exist: %s\n", repoPath)
			os.Exit(1)
		}

		fmt.Printf("Mirroring repository: %s\n", *repoName)

		if err := mirror.MirrorRepository(repoPath, *repoName, mirror.MirrorConfig{
			Enabled: cfg.Mirror.Enabled,
			Targets: cfg.Mirror.Targets,
		}, *async); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to mirror repository: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully mirrored repository: %s\n", *repoName)
	} else {
		fmt.Println("Please specify a repository name or use --all to mirror all repositories")
		os.Exit(1)
	}
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

// listRepositories lists all Git repositories in the repository base directory
func listRepositories(repoBase string) ([]string, error) {
	var repos []string

	// Walk through the repository base directory
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
