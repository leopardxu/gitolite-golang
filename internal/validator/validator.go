package validator

import (
	"errors"
	"path/filepath"
	"strings"
)

// ValidateRepoName validates repository name to prevent path traversal attacks
func ValidateRepoName(repo string) error {
	// Check for path traversal attempts
	if strings.Contains(repo, "..") {
		return errors.New("repository name contains illegal character sequence '..'")
	}

	// Note: We no longer check if it's an absolute path because we now support simplified path format
	// The SSH protocol handler has already converted absolute paths to relative paths

	// Check for special characters
	invalidChars := []string{"\\", ";", "&", "|", ">", "<", "*", "?", "`", "$", "!", "#", "'"} // Added single quote to prevent command injection
	for _, char := range invalidChars {
		if strings.Contains(repo, char) {
			return errors.New("repository name contains illegal character: " + char)
		}
	}

	return nil
}

// ValidatePath ensures path safety to prevent directory traversal
func ValidatePath(basePath, relativePath string) (string, error) {
	// Build full path
	fullPath := filepath.Join(basePath, relativePath)

	// Normalize path
	fullPath = filepath.Clean(fullPath)

	// Ensure the resulting path is still under the base path
	if !strings.HasPrefix(fullPath, basePath) {
		return "", errors.New("path is outside the allowed scope")
	}

	return fullPath, nil
}
