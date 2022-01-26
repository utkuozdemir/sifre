package argon2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
)

const (
	flagSaltLength = "salt-length"
	flagSaltBase64 = "salt-base64"
	flagTime       = "time"
	flagMemory     = "memory"
	flagThreads    = "threads"
	flagKeyLength  = "key-length"
)

var generateCmd = &cobra.Command{
	Use:          "generate",
	Aliases:      []string{"g"},
	Short:        "Generate argon2 hash",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		saltLength, _ := cmd.Flags().GetUint32(flagSaltLength)
		saltBase64, _ := cmd.Flags().GetString(flagSaltBase64)
		time, _ := cmd.Flags().GetUint32(flagTime)
		memory, _ := cmd.Flags().GetUint32(flagMemory)
		threads, _ := cmd.Flags().GetUint8(flagThreads)
		keyLength, _ := cmd.Flags().GetUint32(flagKeyLength)

		var err error
		var salt []byte
		if saltBase64 != "" {
			salt, err = base64.RawStdEncoding.DecodeString(saltBase64)
		} else {
			salt, err = generateRandomBytes(saltLength)
		}

		if err != nil {
			return err
		}

		pwd := []byte(args[0])
		hash := argon2.IDKey(pwd, salt, time, memory, threads, keyLength)

		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(hash)

		encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
			argon2.Version, memory, time, threads, b64Salt, b64Hash)
		fmt.Println(encodedHash)
		return nil
	},
}

func init() {
	Cmd.AddCommand(generateCmd)
	generateCmd.Flags().Uint32P(flagSaltLength, "l", 16,
		"Length of salt to generate in bytes")
	generateCmd.Flags().StringP(flagSaltBase64, "s", "",
		"User-defined salt in base64 format. If specified, --"+flagSaltLength+" is ignored")
	generateCmd.Flags().Uint32P(flagTime, "t", 3, "Time cost")
	generateCmd.Flags().Uint32P(flagMemory, "m", 32*1024, "Memory cost")
	generateCmd.Flags().Uint8(flagThreads, 4, "Threads")
	generateCmd.Flags().Uint32P(flagKeyLength, "k", 32, "Key length")
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
