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
