package silent

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"testing"
)

func runValueSubtestsJSON[F EncryptedValueFactory[T], T any](t *testing.T, name string) {
	t.Run(name, func(t *testing.T) {
		for _, text := range texts {
			orig := F(text)

			enc, err := json.Marshal(orig)
			RequireNoError(t, err)

			if len(text) == 0 {
				RequireEqual(t, string(enc), `""`)
			}

			var dec F
			err = json.Unmarshal(enc, &dec)
			RequireNoError(t, err)

			RequireEqual(t, dec, orig)
		}

	})
}

func runValueSubtestsSQL[F EncryptedValueFactory[T], T any](t *testing.T, name string) {
	t.Run(name, func(t *testing.T) {
		for _, text := range texts {
			orig := F(text)

			// For some reason Go does not understand at compile time that orig is a driver.Valuer.
			// Looks like a bug in the type system. Need to do runtime type assertion here.
			enc, err := any(orig).(driver.Valuer).Value()
			RequireNoError(t, err)

			encBytes, ok := enc.([]byte)
			if !ok {
				t.Fatalf("expected []byte, got %T", enc)
			}

			if len(text) == 0 {
				RequireEqual(t, len(encBytes), 0)
			}

			var dec F
			err = any(&dec).(sql.Scanner).Scan(enc)
			RequireNoError(t, err)

			RequireEqual(t, dec, orig)
		}
	})
}

func TestEncryptedValue(t *testing.T) {
	c1 := MultiKeyCrypter{}
	c1.AddKey(0x1, DecodeBase64(t, "Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))

	type dummy1 struct{}
	type EncryptedValue1 = EncryptedValueFactory[dummy1]
	RegisterCrypterFor[EncryptedValue1](&c1)

	c2 := MultiKeyCrypter{}
	c2.AddKey(0x1, DecodeBase64(t, "Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))
	c2.Bypass = true

	type dummy2 struct{}
	type EncryptedValue2 = EncryptedValueFactory[dummy2]
	RegisterCrypterFor[EncryptedValue2](&c2)

	t.Run("encode/decode", func(t *testing.T) {
		runValueSubtestsJSON[EncryptedValue1](t, "JSON MultiKeyCrypter")
		runValueSubtestsJSON[EncryptedValue2](t, "JSON MultiKeyCrypter bypass")

		runValueSubtestsSQL[EncryptedValue1](t, "SQL MultiKeyCrypter")
		runValueSubtestsSQL[EncryptedValue2](t, "SQL MultiKeyCrypter bypass")
	})

	t.Run("JSON encrypt", func(t *testing.T) {
		orig := EncryptedValue1("Hello, world!")

		enc, err := json.Marshal(orig)
		RequireNoError(t, err)

		if bytes.Contains(enc, orig) {
			t.Fatalf("encrypted text contains plaintext")
		}
	})

	t.Run("JSON bypass", func(t *testing.T) {
		orig := EncryptedValue2("Hello, world!")

		enc, err := json.Marshal(orig)
		RequireNoError(t, err)
		RequireEqual(t, string(enc), `"##Hello, world!"`)
	})

	t.Run("SQL scan string", func(t *testing.T) {
		enc := driver.Value("#Hello, world!")

		var dec EncryptedValue1
		err := dec.Scan(enc)
		RequireNoError(t, err)

		RequireEqual(t, dec, EncryptedValue1("Hello, world!"))
	})

	t.Run("SQL scan nil", func(t *testing.T) {
		enc := driver.Value(nil)

		var dec EncryptedValue1
		err := dec.Scan(enc)
		RequireNoError(t, err)

		RequireEqual(t, dec, EncryptedValue1(""))
	})
}
