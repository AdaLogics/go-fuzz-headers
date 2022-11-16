package logsanitizer

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

type Sanitizer struct {
	logfile             string
	stringsToCheck      []string
	checkInsecureString bool
	fp                  *os.File
}

func NewSanitizer() *Sanitizer {
	s := &Sanitizer{}
	s.stringsToCheck = make([]string, 0)
	s.checkInsecureString = false
	return s
}

// SetLogFile sets the path to the logfile.
func (s *Sanitizer) SetLogFile(logFile string) {
	s.logfile = logFile
}

func (s *Sanitizer) AddInsecureStrings(in ...string) {
	for _, i := range in {
		if !contains(s.stringsToCheck, i) {
			s.stringsToCheck = append(s.stringsToCheck, i)
		}
	}
	s.checkInsecureString = true
}

// GetInsecureStrings is mostly used in the fuzzer to check all
// strings have been added correctly.
func (s *Sanitizer) GetInsecureStrings() []string {
	return s.stringsToCheck
}

func (s *Sanitizer) CheckLogfile() {
	logFile, err := os.Open(s.logfile)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	defer os.Remove(s.logfile)

	rd := bufio.NewReader(logFile)

	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println(err)
			return
		}
		if s.checkInsecureString {
			if s.hasInsecureString(line) {
				panic(createErr(line))
			}
		}
		if hasInsecureLogRUs(line) {
			panic(createErr(line))
		}
		if hasInsecureZap(line) {
			panic(createErr(line))
		}
	}
}

// Checks if the line (which is a line from the log line) contains any
// insecure strings.
func (s *Sanitizer) hasInsecureString(line string) bool {
	if len(s.stringsToCheck) != 0 {
		for _, a := range s.stringsToCheck {
			if strings.Contains(line, a) {
				return true
			}
		}
	}
	return false
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// The idea of this check is to check whether the first characters of
// a line in the log consists of a strings that is similar to the
// characters that logrus has per default. If the first characters
// are similar, then it means that an attacker might be able to create
// fake lines in the log to obfuscate it.
// Adding more insecure strings here will increase the chance of detection.
func hasInsecureLogRUs(line string) bool {
	if len(line) >= 9 {
		if line[0:9] == "INFOFUZZ[" {
			return true
		} else if line[0:9] == "WARNFUZZ[" {
			return true
		} else if line[0:9] == "DEBUFUZZ[" {
			return true
		} else if line[0:9] == "FATAFUZZ[" {
			return true
		}
	}
	if len(line) >= 10 {
		if line[0:9] == "INFO[0Fuz]" {
			return true
		} else if line[0:9] == "WARN[0Fuz]" {
			return true
		} else if line[0:9] == "DEBU[0Fuz]" {
			return true
		} else if line[0:9] == "FATA[0Fuz]" {
			return true
		}
	}
	return false
}

func hasInsecureZap(line string) bool {
	if len(line) >= 9 && line[0:9] == "{\"levell\":" {
		return true
	} else if len(line) >= 13 && line[0:13] == "{\"Fuzzlevel\":" {
		return true
	} else if len(line) >= 12 && line[0:12] == "{\"Fuzlevel\":" {
		return true
	} else if len(line) >= 11 && line[0:11] == "{\"Fulevel\":" {
		return true
	}
	return false
}

func createErr(line string) string {
	var b strings.Builder
	b.WriteString("Insecure string found in the logs.\n")
	b.WriteString(fmt.Sprintf("The following line was found to be insecure: \n\n %s \n", line))
	b.WriteString("This means that an attacker might be able to add lines to the log that seem innocent as a means to hide their tracks.")
	return b.String()
}

// SetupLogSANForLogrus configures Logrus to use the given filename for
// outputting, and returns a Sanitizer configured with the given file.
// It returns an error when failing to create the output file.
func SetupLogSANForLogrus(logFileAbs string) (*Sanitizer, error) {
	logFile, err := os.Create(logFileAbs)
	if err != nil {
		return nil, err
	}
	logrus.SetOutput(logFile)

	logSanitizer := NewSanitizer()
	logSanitizer.SetLogFile(logFileAbs)
	logSanitizer.fp = logFile
	return logSanitizer, nil
}

func (s *Sanitizer) RunSanitizer() {
	s.CheckLogfile()
	s.fp.Close()
	os.Remove(s.logfile)
}
