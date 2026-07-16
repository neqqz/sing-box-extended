package sql

import (
	"encoding/json"
	"fmt"
)

type SliceJSON[T any] []T

func (s *SliceJSON[T]) Scan(src interface{}) error {
	if src == nil {
		*s = nil
		return nil
	}
	var data []byte
	switch v := src.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("sliceJSON.Scan: unsupported type %T", src)
	}
	if len(data) == 0 {
		*s = nil
		return nil
	}
	return json.Unmarshal(data, (*[]T)(s))
}
