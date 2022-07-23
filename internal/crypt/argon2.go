package crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type params struct {
	memory     uint32
	time       uint32
	threads    uint8
	saltLength uint32
	keyLength  uint32
}

type Argon2Generator struct {
	params     *params
	saltBase64 string
}

type Argon2Comparer struct{}

func NewArgon2Generator(memory uint32, time uint32, threads uint8,
	saltLength uint32, keyLength uint32, saltBase64 string,
) *Argon2Generator {
	return &Argon2Generator{
		params: &params{
			memory:     memory,
			time:       time,
			threads:    threads,
			saltLength: saltLength,
			keyLength:  keyLength,
		},
		saltBase64: saltBase64,
	}
}

// NewArgon2Comparer returns a new Argon2Comparer.
func NewArgon2Comparer() (*Argon2Comparer, error) {
	return &Argon2Comparer{}, nil
}

func (a *Argon2Generator) Generate(plaintext string) (string, error) {
	params := a.params

	var err error

	var salt []byte

	if a.saltBase64 != "" {
		salt, err = base64.RawStdEncoding.DecodeString(a.saltBase64)
	} else {
		salt, err = generateRandomBytes(params.saltLength)
	}

	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(plaintext), salt, params.time, params.memory, params.threads, params.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,params=%d$%s$%s",
		argon2.Version, params.memory, params.time, params.threads, b64Salt, b64Hash)

	return encodedHash, nil
}

func (a *Argon2Comparer) Compare(plaintext, hashed string) (bool, error) {
	p, salt, hash, err := decodeHash(hashed)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(plaintext), salt, p.time, p.memory, p.threads, p.keyLength)

	// we don't need to be subtle here for this tool
	if bytes.Equal(hash, otherHash) {
		return true, nil
	}

	return false, nil
}

func (a *Argon2Comparer) CompareBidirectional(str1, str2 string) (bool, error) {
	return CompareBidirectional(str1, str2, a.Compare)
}

func decodeHash(encodedHash string) (*params, []byte, []byte, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 { //nolint:gomnd
		return nil, nil, nil, ErrInvalidHash
	}

	var version int

	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	parameters := &params{} //nolint:exhaustruct

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &parameters.memory, &parameters.time, &parameters.threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	parameters.saltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}

	parameters.keyLength = uint32(len(hash))

	return parameters, salt, hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	buffer := make([]byte, n)

	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}

	return buffer, nil
}
