package access

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gitolite-golang/internal/log"
)

// RepoConfig represents a repository's configuration information
type RepoConfig struct {
	Name        string
	Permissions map[string][]string // user/group -> permission list
	Groups      map[string][]string // group name -> user list
}

// AccessConfig represents the entire access control configuration
type AccessConfig struct {
	Repos  map[string]*RepoConfig // repository name -> repository configuration
	Groups map[string][]string    // global group definitions
}

// ParseConfig parses Gitolite-style configuration file
func ParseConfig(configPath string) (*AccessConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open configuration file: %w", err)
	}
	defer file.Close()

	config := &AccessConfig{
		Repos:  make(map[string]*RepoConfig),
		Groups: make(map[string][]string),
	}

	scanner := bufio.NewScanner(file)
	var currentRepo *RepoConfig

	// Regular expression to match repository definition lines
	repoRegex := regexp.MustCompile(`^repo\s+(.+)$`)
	// Regular expression to match permission definition lines
	permRegex := regexp.MustCompile(`^\s*([-RW+CD]+)\s*=\s*(.+)$`)
	// Regular expression to match group definition lines
	groupRegex := regexp.MustCompile(`^@([\w-]+)\s*=\s*(.+)$`)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Match group definitions
		if matches := groupRegex.FindStringSubmatch(line); len(matches) > 0 {
			groupName := matches[1]
			members := strings.Fields(matches[2])
			config.Groups[groupName] = members
			continue
		}

		// Match repository definitions
		if matches := repoRegex.FindStringSubmatch(line); len(matches) > 0 {
			repoNames := strings.Fields(matches[1])
			for _, name := range repoNames {
				// Handle wildcards
				if strings.Contains(name, "*") {
					// In actual implementation, we would need to expand all repositories matching the wildcard
					// In this simplified version, we use the wildcard as the key
					config.Repos[name] = &RepoConfig{
						Name:        name,
						Permissions: make(map[string][]string),
						Groups:      make(map[string][]string),
					}
				} else {
					config.Repos[name] = &RepoConfig{
						Name:        name,
						Permissions: make(map[string][]string),
						Groups:      make(map[string][]string),
					}
				}
			}
			currentRepo = config.Repos[repoNames[0]]
			continue
		}

		// Match permission definitions
		if currentRepo != nil {
			if matches := permRegex.FindStringSubmatch(line); len(matches) > 0 {
				perm := matches[1]
				users := strings.Fields(matches[2])
				for _, user := range users {
					// Handle group references
					if strings.HasPrefix(user, "@") {
						groupName := user[1:]
						currentRepo.Groups[groupName] = config.Groups[groupName]
					}
					currentRepo.Permissions[user] = append(currentRepo.Permissions[user], perm)
				}
				continue
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	log.Log(log.INFO, fmt.Sprintf("Successfully parsed access control configuration with %d repository definitions", len(config.Repos)))
	return config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *AccessConfig, configPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create configuration directory: %w", err)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create configuration file: %w", err)
	}
	defer file.Close()

	// Write group definitions
	for groupName, members := range config.Groups {
		_, err := fmt.Fprintf(file, "@%s = %s\n", groupName, strings.Join(members, " "))
		if err != nil {
			return fmt.Errorf("failed to write group definitions: %w", err)
		}
	}
	// Write empty line as separator
	_, err = fmt.Fprintln(file, "")
	if err != nil {
		return fmt.Errorf("failed to write to configuration file: %w", err)
	}

	// Write repository definitions
	for _, repo := range config.Repos {
		_, err := fmt.Fprintf(file, "repo %s\n", repo.Name)
		if err != nil {
			return fmt.Errorf("failed to write repository definition: %w", err)
		}

		// Write permission definitions
		for user, perms := range repo.Permissions {
			for _, perm := range perms {
				_, err := fmt.Fprintf(file, "    %s = %s\n", perm, user)
				if err != nil {
					return fmt.Errorf("failed to write permission definition: %w", err)
				}
			}
		}

		// Write empty line as separator
		_, err = fmt.Fprintln(file, "")
		if err != nil {
			return fmt.Errorf("failed to write to configuration file: %w", err)
		}
	}

	log.Log(log.INFO, fmt.Sprintf("Successfully saved access control configuration to %s", configPath))
	return nil
}