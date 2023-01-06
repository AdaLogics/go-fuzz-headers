// Copyright 2023 The go-fuzz-headers Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
