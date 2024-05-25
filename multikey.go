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

type MultiKeyCrypter struct {
	keys      map[uint32][]byte
	lastKeyID uint32

	sioConfigTemplate sio.Config
	Bypass            bool
}

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

func (s *MultiKeyCrypter) Encrypt(data []byte) ([]byte, error) {
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

func (s *MultiKeyCrypter) Decrypt(data []byte) ([]byte, error) {
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

// todo: take and return int?
func (s *MultiKeyCrypter) EncryptedSize(dataSize int) (int, error) {
	if s.Bypass {
		return dataSize + 1, nil
	}

	res, err := sio.EncryptedSize(uint64(dataSize))
	if err != nil {
		return 0, nil
	}
	return int(res) + 5, nil
}

func (s *MultiKeyCrypter) EncryptWriter(w io.Writer) (io.WriteCloser, error) {
	if s.Bypass {
		if err := writeByte(w, '#'); err != nil {
			return nil, err
		}

		return nopCloserWriter{w}, nil
	}

	// write version
	if err := writeByte(w, 1); err != nil {
		return nil, err
	}

	// write key id
	if err := writeUint32(w, s.lastKeyID); err != nil {
		return nil, err
	}

	// write encrypted data
	key := s.keys[s.lastKeyID]
	if key == nil {
		panic("misconfiguration: no keys were added")
	}

	sioConfig := s.sioConfigTemplate
	sioConfig.Key = key[:32] // todo: require exactly 32 bytes key?

	return sio.EncryptWriter(w, sioConfig)
}

func (s *MultiKeyCrypter) DecryptReader(r io.Reader) (io.Reader, error) {
	version, err := readByte(r)
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

type nopCloserWriter struct {
	io.Writer
}

func (nopCloserWriter) Close() error { return nil }
