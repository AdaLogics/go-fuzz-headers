package gofuzzheaders

import (
	"fmt"
	"testing"
)

func TestSQLApi(t *testing.T) {
	data := []byte{1, 1, 0, 1}
	f := NewConsumer(data)
	query, err := f.GetSQLString()
	if err != nil {
		panic(err)
	}
	if query != " action" {
		panic("Should be ' action'")
	}
	fmt.Println("Test 2")
	data2 := []byte{
		222, 255, 0, 100, 10, 64, 2, 0, 0, 0,
		0, 0, 0, 100, 6, 0, 0, 0, 0, 0, 0, 255,
		61, 100, 170, 0, 0,
	}
	f2 := NewConsumer(data2)
	query, err = f2.GetSQLString()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(query)
}
