package gofuzzheaders

import (
	//"fmt"
	"reflect"
	"testing"
)

type TestStruct1 struct {
	Field1 string
	Field2 string
	Field3 []byte
	field4 string
}

func TestStruct_fuzzing1(t *testing.T) {
	data := []byte{0x02, 0x41, 0x42, // Field1
		0x03, 0x41, 0x42, 0x43, // Field2
		0x04,                   // Length of byte slice via make()
		0x41, 0x42, 0x43, 0x44, // Field 3
		0x02, 0x41, 0x42} // FIeld4

	ts1 := TestStruct1{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	//fmt.Printf("%+v\n", ts1)
	if ts1.Field1 != "AB" {
		t.Errorf("ts1.Field1 was %v but should be 'AB'", ts1.Field1)
	}
	if ts1.Field2 != "ABC" {
		t.Errorf("ts1.Field2 was %v but should be 'ABC'", ts1.Field2)
	}
	if string(ts1.Field3) != "ABCD" {
		t.Errorf("ts1.Field3 was %v but should be 'ABCD'", ts1.Field3)
	}
	if string(ts1.field4) != "" {
		t.Errorf("ts1.field4 was %v but should be empty", ts1.field4)
	}
	ts2 := TestStruct1{}
	fuzz2 := NewConsumer(data)
	fuzz2.AllowUnexportedFields()
	err = fuzz2.GenerateStruct(&ts2)
	if err != nil {
		t.Errorf("%v", err)
	}
	if string(ts2.field4) != "AB" {
		t.Errorf("ts2.field4 was %v but should be 'AB'", ts2.field4)
	}
}

type TestStruct2 struct {
	Struct2Field1 string
	Struct2Field2 string
}

type TestStruct3 struct {
	Field1 string
	Field2 string
	Field3 *TestStruct2
}

func TestStruct_fuzzing2(t *testing.T) {
	data := []byte{0x02, 0x41, 0x42, // Field1
		0x03, 0x41, 0x42, 0x43, // Field2
		0x04, 0x41, 0x42, 0x43, 0x44, // Field 3
		0x02, 0x41, 0x42} // FIeld4
	ts3 := TestStruct3{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts3)
	if err != nil {
		t.Errorf("%v", err)
	}
	if string(ts3.Field1) != "AB" {
		t.Errorf("ts3.Field1 was %v but should be 'AB'", ts3.Field1)
	}
	if string(ts3.Field2) != "ABC" {
		t.Errorf("ts3.Field2 was %v but should be 'AB'", ts3.Field2)
	}
	if string(ts3.Field3.Struct2Field1) != "ABCD" {
		t.Errorf("ts3.Field3.Struct2Field1 was %v but should be 'ABCD'", ts3.Field3.Struct2Field1)
	}
	if string(ts3.Field3.Struct2Field2) != "AB" {
		t.Errorf("ts3.Field3.Struct2Field2 was %v but should be 'AB'", ts3.Field3.Struct2Field2)
	}
}

func TestFuzzMap1(t *testing.T) {
	data := []byte{0x02, // Length of map
		0x04, 0x4B, 0x65, 0x79, 0x31, // "Key1"
		0x04, 0x56, 0x61, 0x6C, 0x31, // "Val1"
		0x04, 0x4B, 0x65, 0x79, 0x32, // "Key2"
		0x04, 0x56, 0x61, 0x6C, 0x32} // "Val2"
	var m map[string]string
	fuzz1 := NewConsumer(data)
	err := fuzz1.FuzzMap(&m)
	if err != nil {
		t.Errorf("%v", err)
	}
	if m["Key1"] != "Val1" {
		t.Errorf("m[\"Key1\"] should be \"Val1\" but should be")
	}
	if m["Key2"] != "Val2" {
		t.Errorf("m[\"Key2\"] should be \"Val2\" but should be")
	}
}

func TestFuzzMap2(t *testing.T) {
	data := []byte{0x02, // Length of map
		0x04, 0x4B, 0x65, 0x79, 0x31, // "Key1"
		0x04, 0x56, 0x61, 0x6C, 0x31, // "Val1"
		0x04, 0x4B, 0x65, 0x79, 0x32, // "Key2"
		0x04, 0x56, 0x61, 0x6C, 0x32} // "Val2"
	var m map[string][]byte
	fuzz1 := NewConsumer(data)
	err := fuzz1.FuzzMap(&m)
	if err != nil {
		t.Errorf("%v", err)
	}

	if string(m["Key1"]) != "Val1" {
		t.Errorf("m[\"Key1\"] should be \"Val1\" but should be")
	}
	if string(m["Key2"]) != "Val2" {
		t.Errorf("m[\"Key2\"] should be \"Val2\" but should be")
	}
}

func TestFuzzGetStringFrom(t *testing.T) {
	data := []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66} // "ABCDEF"
	f := NewConsumer(data)
	createdString, err := f.GetStringFrom("abcdefghijklmnopqrstuwxyz123456789-", 6)
	if err != nil {
		t.Errorf("Got an error here but shouldn't")
	}
	if createdString != "345678" {
		t.Errorf("Created string should have been 345678")
	}

	data = []byte{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x2d, 0x2e} // "GHIJKL-."
	f2 := NewConsumer(data)
	createdString, err = f2.GetStringFrom("abcdefghijklmnopqrstuwxyz123456789-", 8)
	if err != nil {
		t.Errorf("Got an error but shouldn't")
	}
	if createdString != "ijklmnkl" {
		t.Errorf("Created string should have been ijklmnkl")
	}
}

func TestUint16(t *testing.T) {
	data := []byte{0x6F, 0x7F, 0x12}
	fuzz1 := NewConsumer(data)
	u16, err := fuzz1.GetUint16()
	if err != nil {
		t.Errorf(err.Error())
	}
	if u16 != 32623 {
		t.Errorf("the u16 should be 32623")
	}

	data = []byte{0x6F, 0x7F, 0x11}
	fuzz2 := NewConsumer(data)
	u16, err = fuzz2.GetUint16()
	if err != nil {
		t.Errorf(err.Error())
	}
	if u16 != 28543 {
		t.Errorf("the u16 should be 28543")
	}

}

func TestGetRune(t *testing.T) {
	data := []byte{0x3, 0x41, 0x42, 0x43}
	fuzz1 := NewConsumer(data)
	newRune, err := fuzz1.GetRune()
	if err != nil {
		t.Errorf(err.Error())
	}
	if string(newRune) != "ABC" {
		t.Errorf("'newRune' should be 'ABC', but is something else")
	}
}

func TestGetFloat32(t *testing.T) {
	data := []byte{0x3, 0x41, 0x42, 0x43, 0x44}
	fuzz1 := NewConsumer(data)
	newFloat, err := fuzz1.GetFloat32()
	if err != nil {
		t.Errorf(err.Error())
	}
	if newFloat != 194.25395 {
		t.Errorf("'newFloat' should be '%f', but is %f\n", 194.25395, newFloat)
	}
}

func TestGetFloat64(t *testing.T) {
	data := []byte{0x3, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}
	fuzz1 := NewConsumer(data)
	newFloat, err := fuzz1.GetFloat64()
	if err != nil {
		t.Errorf(err.Error())
	}
	expectedFloat := 2.3127085096212183e+35
	if newFloat != expectedFloat {
		t.Errorf("'newFloat' should be '%f', but is %f\n", expectedFloat, newFloat)
	}
}

type DemoStructWithFloats struct {
	//field1 float32
	Field1 float32
	Field2 float64
}

func TestStructWithFloats(t *testing.T) {
	data := []byte{0x3, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53}
	fuzz1 := NewConsumer(data)
	ds := &DemoStructWithFloats{}
	err := fuzz1.GenerateStruct(ds)
	if err != nil {
		t.Errorf(err.Error())
	}
	expectedStruct := &DemoStructWithFloats{
		Field1: 194.25395,
		Field2: 5.386597900038134e+25,
	}
	if !reflect.DeepEqual(ds, expectedStruct) {
		t.Errorf("'ds' should be '%f', but is %f\n", expectedStruct, ds)
	}
}
