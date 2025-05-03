package utils

import (
	"fmt" // For error formatting
	"io"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	InfoLogger  *log.Logger
	WarnLogger  *log.Logger
	ErrorLogger *log.Logger
	DebugLogger *log.Logger

	logFile *os.File // Keep a reference to the file handle if needed for closing later
)

const logFileName = "blockchain.log"

func init() {
	var err error
	// Open the log file for appending, create if it doesn't exist
	// Using 0666 permissions allows read/write for owner, group, others
	logFile, err = os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		// If we can't open the log file, log to stderr and panic
		// as logging is likely critical for debugging.
		log.Fatalf("Failed to open log file '%s': %v", logFileName, err)
	}
	// Note: Ideally, the log file should be closed on application shutdown.
	// Since this is in init(), closing cleanly requires extra setup (e.g., a CloseLoggers function called from main).
	// For simplicity here, we rely on OS to close on exit, but add a TODO.
	// TODO: Implement graceful log file closing on application shutdown.

	// Default: Info level logging
	logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "INFO" // Default log level
	}

	// --- Create Log Writers ---
	// io.MultiWriter duplicates writes to all provided writers.
	// NOTE: Color codes WILL be written to the log file with this setup.
	//       Removing colors for the file output requires a more complex setup
	//       (e.g., separate loggers or stripping codes before file write).

	// Info logs go to stdout and the file
	infoMultiWriter := io.MultiWriter(os.Stdout, logFile)
	// Warn logs go to stdout and the file
	warnMultiWriter := io.MultiWriter(os.Stdout, logFile)
	// Error logs go to stderr and the file
	errorMultiWriter := io.MultiWriter(os.Stderr, logFile)
	// Debug logs go to stdout and the file
	debugMultiWriter := io.MultiWriter(os.Stdout, logFile)


	// --- Define Colored Prefixes (applied by log.New) ---
	infoPrefix := color.New(color.FgGreen).SprintFunc()("[INFO] ")
	warnPrefix := color.New(color.FgYellow).SprintFunc()("[WARN] ")
	errorPrefix := color.New(color.FgRed).SprintFunc()("[ERROR] ")
	debugPrefix := color.New(color.FgBlue).SprintFunc()("[DEBUG] ")

	// --- Initialize Loggers with MultiWriters ---
	logFlags := log.Ldate | log.Ltime | log.Lshortfile // Common flags

	InfoLogger = log.New(infoMultiWriter, infoPrefix, logFlags)
	WarnLogger = log.New(warnMultiWriter, warnPrefix, logFlags)
	ErrorLogger = log.New(errorMultiWriter, errorPrefix, logFlags)
	DebugLogger = log.New(debugMultiWriter, debugPrefix, logFlags)

	InfoLogger.Printf("Logging initialized. Level: %s. Output to console and file '%s'", logLevel, logFileName)

	// --- Disable Log Levels Below Threshold ---
	// SetOutput(io.Discard) will stop writing to *both* console and file for that level.
	if logLevel != "DEBUG" {
		DebugLogger.SetOutput(io.Discard)
		DebugLogger.SetFlags(0) // Disable flags too for discarded logs
		// InfoLogger.Println("Debug logging disabled.") // Don't log this if info is also disabled
	}
	if logLevel != "DEBUG" && logLevel != "INFO" {
		InfoLogger.SetOutput(io.Discard)
		InfoLogger.SetFlags(0)
		// WarnLogger.Println("Info logging disabled.")
	}
	if logLevel != "DEBUG" && logLevel != "INFO" && logLevel != "WARN" {
		WarnLogger.SetOutput(io.Discard)
		WarnLogger.SetFlags(0)
		// ErrorLogger.Println("Warn logging disabled.")
	}
	// Error logs are always enabled and retain their MultiWriter output.
}

// Optional: Function to explicitly close the log file if needed
func CloseLogFile() {
	if logFile != nil {
		InfoLogger.Printf("Closing log file: %s", logFileName) // Log before closing
		err := logFile.Close()
		if err != nil {
			// Log closing error to stderr directly as loggers might depend on the file
			fmt.Fprintf(os.Stderr, "Error closing log file '%s': %v\n", logFileName, err)
		}
	}
}