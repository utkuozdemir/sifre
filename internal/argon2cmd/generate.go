package argon2cmd

import (
	"fmt"

	"github.com/utkuozdemir/sifre/internal/crypt"

	"github.com/spf13/cobra"
)

const (
	flagSaltLength = "salt-length"
	flagSaltBase64 = "salt-base64"
	flagTime       = "time"
	flagMemory     = "memory"
	flagThreads    = "threads"
	flagKeyLength  = "key-length"
)

func buildGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			a2 := crypt.NewArgon2Generator(memory, time, threads, saltLength, keyLength, saltBase64)
			hashed, err := a2.Generate(args[0])
			if err != nil {
				return err
			}

			fmt.Println(hashed)
			return nil
		},
	}

	cmd.Flags().Uint32P(flagSaltLength, "l", 16,
		"Length of salt to generate in bytes")
	cmd.Flags().StringP(flagSaltBase64, "s", "",
		"User-defined salt in base64 format. If specified, --"+flagSaltLength+" is ignored")
	cmd.Flags().Uint32P(flagTime, "t", 3, "Time cost")
	cmd.Flags().Uint32P(flagMemory, "m", 32*1024, "Memory cost")
	cmd.Flags().Uint8(flagThreads, 4, "Threads")
	cmd.Flags().Uint32P(flagKeyLength, "k", 32, "Key length")
	return cmd
}
