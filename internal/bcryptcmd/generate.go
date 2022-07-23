package bcryptcmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/utkuozdemir/sifre/internal/crypt"
)

const (
	flagCost = "cost"
)

func buildGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{ //nolint:exhaustruct
		Use:          "generate",
		Aliases:      []string{"g"},
		Short:        "Generate bcrypt hash",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cost, _ := cmd.Flags().GetInt(flagCost)

			bcryptGenerator, err := crypt.NewBcryptGenerator(cost)
			if err != nil {
				return err
			}

			password := args[0]
			hashed, err := bcryptGenerator.Generate(password)
			if err != nil {
				return err
			}

			fmt.Println(hashed) //nolint:forbidigo

			return nil
		},
	}

	cmd.Flags().IntP(flagCost, "c", bcrypt.DefaultCost, "Cost of bcrypt")

	return cmd
}
