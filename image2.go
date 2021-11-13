package fuzz 

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"
	//"unicode/utf8"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

// uncompressedLayer implements partial.UncompressedLayer from raw bytes.
type uncompressedLayer struct {
	diffID    v1.Hash
	mediaType types.MediaType
	content   []byte
}

// DiffID implements partial.UncompressedLayer
func (ul *uncompressedLayer) DiffID() (v1.Hash, error) {
	return ul.diffID, nil
}

// Uncompressed implements partial.UncompressedLayer
func (ul *uncompressedLayer) Uncompressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewBuffer(ul.content)), nil
}

// MediaType returns the media type of the layer
func (ul *uncompressedLayer) MediaType() (types.MediaType, error) {
	return ul.mediaType, nil
}

var _ partial.UncompressedLayer = (*uncompressedLayer)(nil)

var counter = 0
var counter2 = 0

func Fuzz(data []byte) int {
	//fmt.Println(counter)
	f := fuzz.NewConsumer(data)
	img, err := Image(f)
	if err != nil {
		return 0
	}
	counter++
	/*if counter<5000 {
		return 1
	}*/
	runes := "abcdefghijklmnopqrstuvwxyz0123456789_-.ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tagNameString, err := f.GetStringFrom(runes, 126)
	/*if utf8.RuneCountInString(tagNameString)!=0 {
		fmt.Println(utf8.RuneCountInString(tagNameString))
		panic(tagNameString)
	}*/
	if err != nil {
		return 0
	}
	//fmt.Printf("%+v\n", img)
	/*if counter!=200 {
		defer os.Remove(fp.Name())
	}*/
	tag, err := name.NewTag(tagNameString)
	if err != nil {
		return 0
	}

	fp, err := os.Create("tarball")
	if err != nil {
		panic(err)
	}
	defer fp.Close()
	defer os.Remove(fp.Name())
	if err := tarball.WriteToFile(fp.Name(), tag, img); err != nil {
		panic(err)
	}
	fmt.Println("Wrote to ", fp.Name(), "counter2: ", counter2)
	fileData, err := os.ReadFile("tarball")
	if err != nil {
		return 0
	}
	os.Stdout.Write(fileData)

	counter2++
	return 1
}

func Image(f *fuzz.ConsumeFuzzer) (v1.Image, error) {
	adds := make([]mutate.Addendum, 0, 5)
	noOfLayers, err := f.GetInt()
	if err != nil {
		return nil, err
	}
	for i := 0; i < noOfLayers; i++ {
		layer, err := Layer(f, types.DockerLayer)
		if err != nil {
			return nil, err
		}
		author, err := f.GetString()
		if err != nil {
			return nil, err
		}
		comment, err := f.GetString()
		if err != nil {
			return nil, err
		}
		createdBy, err := f.GetString()
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.Addendum{
			Layer: layer,
			History: v1.History{
				Author:    author,
				Comment:   comment,
				CreatedBy: createdBy,
				Created:   v1.Time{Time: time.Now()},
			},
		})
	}

	return mutate.Append(empty.Image, adds...)
}

// Layer returns a layer with pseudo-randomly generated content.
func Layer(f *fuzz.ConsumeFuzzer, mt types.MediaType) (v1.Layer, error) {
	//fileName := fmt.Sprintf("random_file_%d.txt", mrand.Int())

	// Hash the contents as we write it out to the buffer.
	var b bytes.Buffer
	hasher := sha256.New()
	mw := io.MultiWriter(&b, hasher)

	// write random files
	noOfFiles, err := f.GetInt()
	if err != nil {
		return nil, err
	}
	if noOfFiles%50==0 {
		return nil, fmt.Errorf("No files to be created")
	}
	for i:=0;i<noOfFiles%50;i++ {
		// Write a single file with a random name and random contents.
		fileName, err := f.GetString()
		if err != nil {
			return nil, err
		}
		randBytes, err := f.GetBytes()
		if err != nil {
			return nil, err
		}
		tw := tar.NewWriter(mw)
		if err := tw.WriteHeader(&tar.Header{
			Name:     fileName,
			Size:     int64(len(randBytes)),
			Typeflag: tar.TypeRegA,
		}); err != nil {
			return nil, err
		}
		if _, err := io.CopyN(tw, bytes.NewReader(randBytes), int64(len(randBytes))); err != nil {
			return nil, err
		}
		if err := tw.Close(); err != nil {
			return nil, err
		}
	}

	h := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))),
	}

	return partial.UncompressedToLayer(&uncompressedLayer{
		diffID:    h,
		mediaType: mt,
		content:   b.Bytes(),
	})
}