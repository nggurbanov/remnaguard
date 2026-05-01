package jsonpolicy

import (
	"strings"
	"testing"
)

func TestDecodeObjectNoDuplicateKeysRejectsDuplicate(t *testing.T) {
	_, err := DecodeObjectNoDuplicateKeys(strings.NewReader(`{"username":"a","username":"b"}`), 1024)
	if err == nil {
		t.Fatal("expected duplicate key rejection")
	}
}

func TestValidateFieldsRejectsUnknown(t *testing.T) {
	obj, err := DecodeObjectNoDuplicateKeys(strings.NewReader(`{"username":"a","root":true}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFields(obj, []string{"username"}); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}
