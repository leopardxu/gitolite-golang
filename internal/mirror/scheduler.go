package mirror

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"

	"github.com/robfig/cron/v3"
)

// MirrorScheduler handles scheduled mirror operations
type MirrorScheduler struct {
	cron      *cron.Cron
	repoBase  string
	mirrorCfg MirrorConfig
	jobIDs    map[string]cron.EntryID
	interval  string
}

// NewMirrorScheduler creates a new mirror scheduler
func NewMirrorScheduler(repoBase string, mirrorCfg MirrorConfig, interval string) *MirrorScheduler {
	if interval == "" {
		interval = "@hourly" // Default to hourly if not specified
	}

	return &MirrorScheduler{
		cron:      cron.New(),
		repoBase:  repoBase,
		mirrorCfg: mirrorCfg,
		jobIDs:    make(map[string]cron.EntryID),
		interval:  interval,
	}
}

// Start starts the mirror scheduler
func (ms *MirrorScheduler) Start() {
	// If mirroring is not enabled, return immediately
	if !ms.mirrorCfg.Enabled || len(ms.mirrorCfg.Targets) == 0 {
		log.Log(log.INFO, "Mirror scheduler not started: mirroring is disabled or no targets configured")
		return
	}

	// Add scheduled job for all repositories
	jobID, err := ms.cron.AddFunc(ms.interval, func() {
		ms.mirrorAllRepositories()
	})

	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to schedule mirror job: %v", err))
		return
	}

	ms.jobIDs["all"] = jobID
	ms.cron.Start()

	log.Log(log.INFO, fmt.Sprintf("Mirror scheduler started with interval: %s", ms.interval))
}

// Stop stops the mirror scheduler
func (ms *MirrorScheduler) Stop() {
	if ms.cron != nil {
		ms.cron.Stop()
		log.Log(log.INFO, "Mirror scheduler stopped")
	}
}

// mirrorAllRepositories mirrors all repositories
func (ms *MirrorScheduler) mirrorAllRepositories() {
	log.Log(log.INFO, "Starting scheduled mirror operation for all repositories")

	// Get all repositories
	repos, err := listRepositories(ms.repoBase)
	if err != nil {
		log.Log(log.ERROR, fmt.Sprintf("Failed to list repositories: %v", err))
		return
	}

	// Mirror each repository
	for _, repo := range repos {
		repoPath := filepath.Join(ms.repoBase, repo+".git")
		log.Log(log.INFO, fmt.Sprintf("Scheduled mirror for repository: %s", repo))

		// Mirror the repository to all configured targets
		if err := MirrorRepository(repoPath, repo, ms.mirrorCfg, false); err != nil {
			log.Log(log.ERROR, fmt.Sprintf("Scheduled mirror failed for repository %s: %v", repo, err))
		}
	}

	log.Log(log.INFO, "Completed scheduled mirror operation for all repositories")
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

// StartMirrorScheduler starts the mirror scheduler with the given configuration
func StartMirrorScheduler(repoBase string, mirrorCfg MirrorConfig, interval string) *MirrorScheduler {
	scheduler := NewMirrorScheduler(repoBase, mirrorCfg, interval)
	scheduler.Start()
	return scheduler
}
