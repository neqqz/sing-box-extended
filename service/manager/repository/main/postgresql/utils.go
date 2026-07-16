package postgresql

import (
	"encoding/json"
)

func marshalStringSlice(values []string) ([]byte, error) {
	if values == nil {
		values = []string{}
	}
	return json.Marshal(values)
}
