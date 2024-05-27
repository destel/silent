package silent

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

type EncryptedValueFactory[T any] []byte

type dummy struct{}
type EncryptedValue = EncryptedValueFactory[dummy]

type Crypter interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type crypterMapping struct {
	Zero    any
	Crypter Crypter
}

var crypters []crypterMapping

func RegisterCrypterFor[F EncryptedValueFactory[T], T any](c Crypter) {
	// this full scan loop is about 10x faster than map in this scenario
	// todo: add benchmark
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

func (v EncryptedValueFactory[T]) String() string {
	return fmt.Sprintf("EncryptedValue(%s)", string(v))
}

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

func (v EncryptedValueFactory[T]) Value() (driver.Value, error) {
	if len(v) == 0 {
		return []byte{}, nil
	}

	crypter := getCrypterFor[T]()

	encData, err := crypter.Encrypt(v)
	return encData, err
}

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
