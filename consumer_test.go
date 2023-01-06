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

package gofuzzheaders

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"testing"
)

type TestStruct1 struct {
	Field1 string
	Field2 string
	Field3 []byte
}

func TestStruct_fuzzing1(t *testing.T) {
	data := []byte{
		0x03, 0x41, 0x42, 0x43, // Length and data of field 1 (= 2)
		0x03, 0x41, 0x42, 0x43, // Length and data of field 2 (= 3)
		0x01, 0x41, // Field3
	}

	ts1 := TestStruct1{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	if ts1.Field1 != "ABC" {
		t.Errorf("ts1.Field1 was %v but should be 'AB'", []byte(ts1.Field1))
	}
	if ts1.Field2 != "ABC" {
		t.Errorf("ts1.Field2 was %v but should be 'ABC'", ts1.Field2)
	}
	if string(ts1.Field3) != "A" {
		t.Errorf("ts1.Field3 was %v but should be 'A'", ts1.Field3)
	}
}

// Tests that we can create long byte slices in structs
func TestStruct_fuzzing2(t *testing.T) {
	data := []byte{
		0x03, 0x41, 0x42, 0x43, // Length field 1 (= 3)
		0x03, 0x41, 0x42, 0x43, // Content of Field3
		0x50,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // All of this
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // should go
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // into Field3
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	}

	ts1 := TestStruct1{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	if ts1.Field1 != "ABC" {
		t.Errorf("ts1.Field1 was %v but should be 'ABC'", ts1.Field1)
	}
	if ts1.Field2 != "ABC" {
		t.Errorf("ts1.Field2 was %v but should be 'ABC'", ts1.Field2)
	}
	if len(ts1.Field3) != 80 {
		t.Errorf("ts1.Field3 was %v but should be 'ABCD'", ts1.Field3)
	}
}

func TestTarBytes(t *testing.T) {

	data := []byte{
		0x01,                                           // number of files
		0x08,                                           // Length of first file name
		0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, // "manifest"
		0x09,                                           // Length of file body
		0x01,                                           // shouldUseLargeFileBody (I think)
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // file contents
		0x04, 0x02, 0x03,
		0x00, // type flag
		0x01, 0x01, 0x01, 0x01,
	}
	f := NewConsumer(data)
	tb, err := f.TarBytes()
	if err != nil {
		t.Fatalf("Fatal: %s", err)
	}

	tarReader := tar.NewReader(bytes.NewReader(tb))

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Println(err)
			t.Fatal(err)
		}
		if header.Typeflag != 48 {
			t.Fatal("typeflag should be 48 (which is a tar.TypeReg)")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			t.Fatal("Should not be a directory")
		case tar.TypeReg:
			if header.Name != "manifest" {
				t.Fatalf("file name was %s but should be 'manifest'\n", header.Name)
			}
		}
	}
}
