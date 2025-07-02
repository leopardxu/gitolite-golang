package log

import (
	"compress/gzip"
	"io"
	"os"
)

// CompressLog compresses log file
func CompressLog(logPath string) error {
	file, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzFile, err := os.Create(logPath + ".gz")
	if err != nil {
		return err
	}
	defer gzFile.Close()

	gzWriter := gzip.NewWriter(gzFile)
	defer gzWriter.Close()

	if _, err := io.Copy(gzWriter, file); err != nil {
		return err
	}

	return os.Remove(logPath)
}
