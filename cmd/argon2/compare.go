package argon2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/spf13/cobra"
)

const (
	flagQuiet = "quiet"
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

var compareCmd = &cobra.Command{
	Use:          "compare",
	Aliases:      []string{"c"},
	Short:        "Compare password with argon2 hash",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		quiet, err := cmd.Flags().GetBool(flagQuiet)
		if err != nil {
			return err
		}

		match1, err1 := compareHashAndPassword(args[0], args[1])
		match2, err2 := compareHashAndPassword(args[1], args[0])

		if err1 != nil && err2 != nil {
			return fmt.Errorf("%s\n%s", err1, err2)
		}

		if (match1 || match2) && !quiet {
			fmt.Println("Matched!")
			return nil
		}

		return errors.New("no match")
	},
}

func init() {
	Cmd.AddCommand(compareCmd)
	compareCmd.Flags().BoolP(flagQuiet, "q", false, "Do not write to stdout")
}

func compareHashAndPassword(encodedHash, password string) (match bool, err error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, p.keyLength)

	// we don't need to be subtle here for this tool
	if bytes.Equal(hash, otherHash) {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}
