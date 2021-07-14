package gofuzzheaders

import (
	//"fmt"
	"testing"
)

type TestStruct1 struct {
	Field1          string
	Field2   		string
	Field3			[]byte
	field4			string
}

func TestStruct_fuzzing1(t *testing.T) {
	data := []byte{0x02, 0x41, 0x42, // Field1
				   0x03, 0x41, 0x42, 0x43, // Field2
				   0x04, // Length of byte slice via make()
				   0x41, 0x42, 0x43, 0x44, // Field 3
				   0x02, 0x41, 0x42} // FIeld4
	
	ts1 := TestStruct1{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	//fmt.Printf("%+v\n", ts1)
	if ts1.Field1!="AB" {
		t.Errorf("ts1.Field1 was %v but should be 'AB'", ts1.Field1)
	}
	if ts1.Field2!="ABC" {
		t.Errorf("ts1.Field2 was %v but should be 'ABC'", ts1.Field2)
	}
	if string(ts1.Field3)!="ABCD" {
		t.Errorf("ts1.Field3 was %v but should be 'ABCD'", ts1.Field3)
	}
	if string(ts1.field4)!="" {
		t.Errorf("ts1.field4 was %v but should be empty", ts1.field4)
	}
	ts2 := TestStruct1{}
	fuzz2 := NewConsumer(data)
	fuzz2.AllowUnexportedFields()
	err = fuzz2.GenerateStruct(&ts2)
	if err != nil {
		t.Errorf("%v", err)
	}
	if string(ts2.field4)!="AB" {
		t.Errorf("ts2.field4 was %v but should be 'AB'", ts2.field4)
	}
}

type TestStruct2 struct {
	Struct2Field1   string
	Struct2Field2   string
}

type TestStruct3 struct {
	Field1          string
	Field2   		string
	Field3 			*TestStruct2
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
	if string(ts3.Field1)!="AB" {
		t.Errorf("ts3.Field1 was %v but should be 'AB'", ts3.Field1)
	}
	if string(ts3.Field2)!="ABC" {
		t.Errorf("ts3.Field2 was %v but should be 'AB'", ts3.Field2)
	}
	if string(ts3.Field3.Struct2Field1)!="ABCD" {
		t.Errorf("ts3.Field3.Struct2Field1 was %v but should be 'ABCD'", ts3.Field3.Struct2Field1)
	}
	if string(ts3.Field3.Struct2Field2)!="AB" {
		t.Errorf("ts3.Field3.Struct2Field2 was %v but should be 'AB'", ts3.Field3.Struct2Field2)
	}
}