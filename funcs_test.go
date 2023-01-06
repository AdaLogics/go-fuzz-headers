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

/*
import (
	"testing"
)

type TestStructFuncs1 struct {
	Field1 string
	Field2 string
	Field3 []byte
	field4 string
}

type TestStructFuncs2 struct {
	Field1 []byte
}

type TestStructFuncs3 struct {
	Field1 *TestStructFuncs4
	Field2 string
}

type TestStructFuncs4 struct {
	Field1 string
	Field2 string
}

func TestStruct_fuzzing_CustomFuncs1(t *testing.T) {
	data := []byte{
		0x02, 0x41, 0x42, // Field1
		0x03, 0x41, 0x42, 0x43, // Field2
	}

	ts1 := TestStructFuncs3{}
	fuzz1 := NewConsumer(data)
	testfuncss := testFuncs()
	fuzz1.AddFuncs(testfuncss)
	err := fuzz1.GenerateWithCustom(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	if ts1.Field1.Field1 != "AB" {
		t.Errorf("ts1.Field1.Field1 was %v but should be 'AB'", ts1.Field1)
	}
	if ts1.Field1.Field2 != "staticString" {
		t.Errorf("ts1.Field1.Field2 was %v but should be 'staticString'", ts1.Field1)
	}
	if ts1.Field2 != "ABC" {
		t.Errorf("ts1.Field1 was %v but should be 'ABC'", ts1.Field1)
	}
}

func testFuncs() []interface{} {
	return []interface{}{
		func(j *TestStructFuncs4, c Continue) error {
			newString, err := c.F.GetString()
			if err != nil {
				return err
			}
			j.Field1 = newString
			j.Field2 = "staticString"
			return nil
		},
	}
}
*/
