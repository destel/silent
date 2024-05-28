package silent

import (
	"bytes"
	"errors"
	"io"

	"github.com/minio/sio"
)

var (
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrUnknownKey         = errors.New("unknown key id")
)

// MultiKeyCrypter is a [Crypter] implementation that supports multiple encryption keys and seamless key rotation.
// It uses the most recently added key for encryption and automatically selects the appropriate key for decryption
// based on the key ID embedded in the encrypted data.
// This design simplifies adding new keys, while maintaining compatibility with previously used keys.
type MultiKeyCrypter struct {
	keys      map[uint32][]byte
	lastKeyID uint32

	sioConfigTemplate sio.Config

	// Bypass be set to true to bypass the encryption and keep the values human-readable.
	// In bypass mode, the data is prefixed with a '#' character.
	Bypass bool
}

// AddKey adds a new key to the crypter.
// The keyID must be unique and the key must be at least 32 bytes long.
func (s *MultiKeyCrypter) AddKey(keyID uint32, key []byte) {
	if s.keys == nil {
		s.sioConfigTemplate.MinVersion = sio.Version20

		s.keys = make(map[uint32][]byte)
	}

	if len(key) < 32 {
		panic("misconfiguration: key must be at least 32 bytes")
	}

	if s.keys[keyID] != nil {
		panic("misconfiguration: all key ids must be unique")
	}

	s.keys[keyID] = key
	s.lastKeyID = keyID
}

// Encrypt encrypts the data using the last added key.
// Encrypted data will contain the key ID and the encrypted data.
func (s *MultiKeyCrypter) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	size, err := s.EncryptedSize(len(data))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Grow(size)
	w, err := s.EncryptWriter(&buf)
	if err != nil {
		return nil, err
	}
	defer w.Close() // it's safe to do double close

	if _, err := w.Write(data); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts the data.
// The key is automatically selected based on the key ID embedded in the data.
func (s *MultiKeyCrypter) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	size := len(data)
	var buf bytes.Buffer
	buf.Grow(size)

	r, err := s.DecryptReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncryptedSize returns the size of the encrypted data.
func (s *MultiKeyCrypter) EncryptedSize(dataSize int) (int, error) {
	if dataSize == 0 {
		return 0, nil
	}

	if s.Bypass {
		return dataSize + 1, nil
	}

	res, err := sio.EncryptedSize(uint64(dataSize))
	if err != nil {
		return 0, nil
	}
	return int(res) + 5, nil
}

// EncryptWriter is a streaming version of [Encrypt].
func (s *MultiKeyCrypter) EncryptWriter(w io.Writer) (io.WriteCloser, error) {
	ew := &dynamicWriter{}

	ew.CloseFunc = func() error {
		if closer, ok := w.(io.Closer); ok {
			ew.CloseFunc = nil
			return closer.Close()
		}

		ew.CloseFunc = nil
		return nil
	}

	ew.WriteFunc = func(p []byte) (n int, err error) {
		if len(p) == 0 {
			return 0, nil
		}

		if s.Bypass {
			if err := writeByte(w, '#'); err != nil {
				return 0, err
			}

			// forward this and subsequent calls directly to w
			ew.WriteFunc = w.Write
			return ew.Write(p)
		}

		if err := writeByte(w, 1); err != nil {
			return 0, err
		}

		if err := writeUint32(w, s.lastKeyID); err != nil {
			return 0, err
		}

		key := s.keys[s.lastKeyID]
		if key == nil {
			panic("misconfiguration: no keys were added")
		}

		sioConfig := s.sioConfigTemplate
		sioConfig.Key = key[:32] // todo: require exactly 32 bytes key?

		sioWriter, err := sio.EncryptWriter(w, sioConfig)
		if err != nil {
			return 0, err
		}

		// forward this and subsequent calls directly to sioWriter
		ew.WriteFunc = sioWriter.Write
		ew.CloseFunc = sioWriter.Close
		return ew.Write(p)
	}

	return ew, nil
}

// DecryptReader is a streaming version of [Decrypt].
func (s *MultiKeyCrypter) DecryptReader(r io.Reader) (io.Reader, error) {
	version, err := readByte(r)
	if errors.Is(err, io.EOF) {
		return bytes.NewReader(nil), nil
	}
	if err != nil {
		return nil, err
	}

	switch version {
	case '#':
		return r, nil

	case 1:
		keyID, err := readUint32(r)
		if err != nil {
			return nil, err
		}

		key := s.keys[keyID]
		if key == nil {
			return nil, ErrUnknownKey
		}

		sioConfig := s.sioConfigTemplate
		sioConfig.Key = key[:32] // todo: require exactly 32 bytes key?

		// sio retunrns an errorfor empty data, so we need to handle it here
		var firstByte [1]byte
		_, err = io.ReadFull(r, firstByte[:])
		if errors.Is(err, io.EOF) {
			return bytes.NewReader(nil), nil
		}
		if err != nil {
			return nil, err
		}

		// "put back" the first byte
		r = io.MultiReader(bytes.NewReader(firstByte[:]), r)

		return sio.DecryptReader(r, sioConfig) // todo: properly handle errors

	default:
		return nil, ErrUnsupportedVersion
	}
}

func readByte(r io.Reader) (byte, error) {
	var data [1]byte
	_, err := io.ReadFull(r, data[:])
	if err != nil {
		return 0, err
	}

	return data[0], nil
}

func writeByte(w io.Writer, value byte) error {
	data := [1]byte{value}
	_, err := w.Write(data[:])
	return err

}

func readUint32(r io.Reader) (uint32, error) {
	var data [4]byte
	_, err := io.ReadFull(r, data[:])
	if err != nil {
		return 0, err
	}

	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24, nil
}

func writeUint32(w io.Writer, value uint32) error {
	// little-endian
	data := [4]byte{
		byte(value),
		byte(value >> 8),
		byte(value >> 16),
		byte(value >> 24),
	}
	_, err := w.Write(data[:])
	return err
}

type dynamicWriter struct {
	WriteFunc func(p []byte) (n int, err error)
	CloseFunc func() error
}

func (w *dynamicWriter) Write(p []byte) (n int, err error) {
	return w.WriteFunc(p)
}

func (w *dynamicWriter) Close() error {
	if w.CloseFunc == nil {
		return nil
	}
	return w.CloseFunc()
}
