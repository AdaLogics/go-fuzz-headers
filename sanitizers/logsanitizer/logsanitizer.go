package logsanitizer

import (
	"bufio"
	"io"
	"os"
	"strings"
)

type Sanitizer struct {
	logfile             string
	stringsToCheck      []string
	checkInsecureString bool
}

func NewSanitizer() *Sanitizer {
	s := &Sanitizer{}
	s.stringsToCheck = make([]string, 0)
	s.checkInsecureString = false
	return s
}

func (s *Sanitizer) CheckInsecureString() {
	s.checkInsecureString = true
}

// Takes the path to the logfile
func (s *Sanitizer) SetLogFile(logFile string) {
	fp, err := os.Create(logFile)
	if err != nil {
		panic(err)
	}
	fp.Close()
	s.logfile = logFile
}

func (s *Sanitizer) AddInsecureStrings(in ...string) {
	for _, i := range in {
		if !contains(s.stringsToCheck, i) {
			s.stringsToCheck = append(s.stringsToCheck, i)
		}
	}
}

func (s *Sanitizer) CheckLogfile() {
	logFile, err := os.OpenFile(s.logfile, os.O_RDONLY, os.ModePerm)
	if err != nil {
		panic(err)
	}
	rd := bufio.NewReader(logFile)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			logFile.Close()
			return
		}
		if s.checkInsecureString {
			if s.containsInsecureString(line) {
				panic("Insecure string found")
			}
		}
	}
	logFile.Close()
	os.Remove(s.logfile)
}

// Checks if the line (which is a line from the log line) contains any
// insecure strings.
func (s *Sanitizer) containsInsecureString(line string) bool {
	if len(s.stringsToCheck) == 0 {
		return false
	}
	for _, a := range s.stringsToCheck {
		if strings.Contains(line, a) {
			return true
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
