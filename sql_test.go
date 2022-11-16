package gofuzzheaders

import (
	"testing"
)

func TestSQLAPI(t *testing.T) {
	t.Run("Test 1", func(t *testing.T) {
		data := []byte{1, 1, 0, 1}
		f := NewConsumer(data)
		query, err := f.GetSQLString()
		if err != nil {
			t.Error(err)
		}
		if query != " action" {
			t.Errorf("expected ' action', got: '%s'", query)
		}
	})
	t.Run("Test 2", func(t *testing.T) {
		data := []byte{
			222, 255, 0, 100, 10, 64, 2, 0, 0, 0,
			0, 0, 0, 100, 6, 0, 0, 0, 0, 0, 0, 255,
			61, 100, 170, 0, 0,
		}
		f := NewConsumer(data)
		query, err := f.GetSQLString()
		if err != nil {
			t.Error(err)
		}
		t.Log(query)
	})
}
