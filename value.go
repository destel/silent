package silent

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// EncryptedValueFactory is a generic type factory for creating custom [EncryptedValue] types.
// To define a new EncryptedValue type, create a unique dummy type and use it as the generic parameter:
//
//	type dummy1 struct{} // this won't be used in your code
//	type MyEncryptedValue = EncryptedValueFactory[dummy1]
type EncryptedValueFactory[T any] []byte

type dummy struct{}

// EncryptedValue is a built-in type that is automatically encrypted when written to, and decrypted when read from, the database.
type EncryptedValue = EncryptedValueFactory[dummy]

// Crypter is an interface that can be implemented to provide a custom encryption strategy
type Crypter interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type crypterMapping struct {
	Zero    any
	Crypter Crypter
}

var crypters []crypterMapping

// BindCrypterTo binds a crypter instance to a specific EncryptedValue type.
// Example usage:
//
//	BindCrypterTo[silent.EncryptedValue](&crypter)
func BindCrypterTo[F EncryptedValueFactory[T], T any](c Crypter) {
	// this full scan loop is about 10x faster than map in this scenario
	for _, c := range crypters {
		if _, ok := c.Zero.(T); ok {
			panic("misconfigurtion: crypter already registered")
		}
	}

	var zero T
	crypters = append(crypters, crypterMapping{
		Zero:    zero,
		Crypter: c,
	})
}

func getCrypterFor[T any]() Crypter {
	for _, c := range crypters {
		if _, ok := c.Zero.(T); ok {
			return c.Crypter
		}
	}

	panic("misconfiguration: no crypter registered for this type")
}

// String returns a string representation of the EncryptedValue
func (v EncryptedValueFactory[T]) String() string {
	return fmt.Sprintf("EncryptedValue(%s)", string(v))
}

// MarshalJSON encrypts the value and marshals it into JSON format.
//   - If the value is empty, it is marshalled as a JSON representation of an empty string ("").
//   - If the encrypted data forms a valid UTF-8 string, it is marshaled as a string prefixed with '#'.
//   - Otherwise, the data is marshaled as a base64-encoded string.
func (v EncryptedValueFactory[T]) MarshalJSON() ([]byte, error) {
	if len(v) == 0 {
		return []byte(`""`), nil
	}

	crypter := getCrypterFor[T]()

	encData, err := crypter.Encrypt(v)
	if err != nil {
		return nil, err
	}

	if utf8.Valid(encData) {
		var buf bytes.Buffer
		buf.Grow(len(encData) + 3)

		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)

		err := enc.Encode("#" + string(encData)) // will be encoded as string prepended by #
		if err != nil {
			return nil, err
		}

		res := buf.Bytes()
		res = res[:len(res)-1] // trim trailing newline
		return res, nil
	} else {
		return json.Marshal(encData) // will be encoded as base64
	}

}

// UnmarshalJSON decrypts the value from JSON.
func (v *EncryptedValueFactory[T]) UnmarshalJSON(data []byte) error {
	if s := string(data); s == `""` || s == `null` {
		*v = nil
		return nil
	}

	crypter := getCrypterFor[T]()

	var encData []byte

	// string or base64?
	if len(data) >= 2 && data[1] == '#' {
		var target string
		err := json.Unmarshal(data, &target)
		if err != nil {
			return err
		}

		encData = []byte(target[1:])
	} else {
		err := json.Unmarshal(data, &encData)
		if err != nil {
			return err
		}
	}

	var err error
	*v, err = crypter.Decrypt(encData)
	return err
}

// Value is a driver.Valuer implementation. It encrypts the value and returns a byte slice suitable for database storage.
func (v EncryptedValueFactory[T]) Value() (driver.Value, error) {
	if len(v) == 0 {
		return []byte{}, nil
	}

	crypter := getCrypterFor[T]()

	encData, err := crypter.Encrypt(v)
	return encData, err
}

// Scan is a sql.Scanner implementation. It decrypts the value from the database.
func (v *EncryptedValueFactory[T]) Scan(value interface{}) error {
	crypter := getCrypterFor[T]()

	switch t := value.(type) {
	case nil:
		*v = nil
		return nil
	case []byte:
		if len(t) == 0 {
			*v = nil
			return nil
		}

		data, err := crypter.Decrypt(t)
		if err != nil {
			return err
		}

		*v = data
		return nil

	case string:
		if t == "" {
			*v = nil
			return nil
		}

		data, err := crypter.Decrypt([]byte(t))
		if err != nil {
			return err
		}

		*v = data
		return nil
	default:
		return fmt.Errorf("unable to scan %T into EncryptedValue", value)
	}
}
