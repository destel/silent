package silent

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func DecodeBase64(t *testing.T, s string) []byte {
	res, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Errorf("error decoding base64: %v", err)
	}
	return res
}

func RequireEqual(t *testing.T, actual, expected any) {
	t.Helper()

	ra := reflect.ValueOf(actual)
	re := reflect.ValueOf(expected)

	if ra.Kind() == reflect.Slice && re.Kind() == reflect.Slice {
		if ra.Len() != re.Len() {
			t.Fatalf("expected %v, got %v", expected, actual)
		}

		for i := 0; i < ra.Len(); i++ {
			if ra.Index(i).Interface() != re.Index(i).Interface() {
				t.Fatalf("expected %v, got %v", expected, actual)
			}
		}
		return
	}

	if actual != expected {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func RequireTrue(t *testing.T, actual bool) {
	t.Helper()
	RequireEqual(t, actual, true)
}

func RequireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func RequireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
