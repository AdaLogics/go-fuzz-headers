package examples

import (
	"io/ioutil"
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzCreateFiles(data []byte) int {
	tmpDir, err := ioutil.TempDir("dir", "prefix")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(tmpDir)
	f := fuzz.NewConsumer(data)
	err = f.CreateFiles(tmpDir)
	if err != nil {
		return 0
	}
	return 1
}
