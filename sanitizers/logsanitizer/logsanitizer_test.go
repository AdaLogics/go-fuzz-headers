package logsanitizer

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSanitizer(t *testing.T) {
	tmpDir := t.TempDir()
	logFileAbs := filepath.Join(tmpDir, "test-logfile")
	err := os.WriteFile(logFileAbs, []byte("\nDEBUFUZZ2[0027]\nDEBUFUZZ[0027]\n"), 0o666)
	if err != nil {
		t.Fatal(err)
	}

	// set up sanitizer
	s := NewSanitizer()

	// set up log file in sanitizer
	s.SetLogFile(logFileAbs)

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
			if !strings.Contains(err, "Insecure string found") {
				t.Error(err)
			}
		} else {
			t.Error("we should have recovered a panic")
		}
	}()

	// Do the log file checking. This will usually be done
	// in a defer statement in the fuzzer.
	s.CheckLogfile()
}
