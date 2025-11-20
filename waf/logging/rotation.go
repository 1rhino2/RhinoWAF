package logging

import (
	"io"
	"log"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Config holds log rotation configuration
type Config struct {
	Enabled    bool   `json:"enabled"`
	Filename   string `json:"filename"`    // Log file path
	MaxSize    int    `json:"max_size"`    // Max size in MB before rotation (default: 100)
	MaxBackups int    `json:"max_backups"` // Max number of old files to keep (default: 3)
	MaxAge     int    `json:"max_age"`     // Max days to keep old files (default: 28)
	Compress   bool   `json:"compress"`    // Compress rotated files (default: true)
}

// SetupRotation configures log rotation for a log file
func SetupRotation(config Config) io.Writer {
	if !config.Enabled {
		return os.Stdout
	}

	// Set defaults
	if config.MaxSize == 0 {
		config.MaxSize = 100
	}
	if config.MaxBackups == 0 {
		config.MaxBackups = 3
	}
	if config.MaxAge == 0 {
		config.MaxAge = 28
	}

	logger := &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}

	log.Printf("Log rotation enabled: %s (max_size=%dMB, max_backups=%d, max_age=%dd, compress=%v)",
		config.Filename, config.MaxSize, config.MaxBackups, config.MaxAge, config.Compress)

	return logger
}

// MultiWriter creates a writer that writes to both stdout and file
func MultiWriter(file io.Writer) io.Writer {
	return io.MultiWriter(os.Stdout, file)
}
