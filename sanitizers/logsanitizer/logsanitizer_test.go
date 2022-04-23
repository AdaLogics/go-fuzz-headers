package logsanitizer

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestSanitizer(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			var err string
			switch r.(type) {
			case string:
				err = r.(string)
			case runtime.Error:
				err = r.(runtime.Error).Error()
			case error:
				err = r.(error).Error()
			}
			if strings.Contains(err, "Insecure string found") {
				// Getting here means that the test passed
			} else {
				panic(err)
			}
		} else {
			panic("We should have recovered a panic")
		}
	}()

	logFileAbs := "/tmp/test-logfile"
	logFile, err := os.Create(logFileAbs)
	if err != nil {
		panic(err)
	}
	logFile.WriteString("\nDEBUFUZZ2[0027]\n")
	logFile.WriteString("DEBUFUZZ[0027]\n")
	logFile.Close()

	// set up sanitizer
	s := NewSanitizer()

	// set up log file in sanitizer
	s.SetLogFile(logFileAbs)

	// Do the log file checking. This will usually be done
	// in a defer statement in the fuzzer.
	s.CheckLogfile()
}
