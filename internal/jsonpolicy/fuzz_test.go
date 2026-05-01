package jsonpolicy

import (
	"strings"
	"testing"
)

func FuzzDecodeObjectNoDuplicateKeys(f *testing.F) {
	f.Add(`{"username":"alice"}`)
	f.Add(`{"username":"alice","username":"bob"}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, body string) {
		_, _ = DecodeObjectNoDuplicateKeys(strings.NewReader(body), 4096)
	})
}
