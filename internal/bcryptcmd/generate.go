package bcryptcmd

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/utkuozdemir/sifre/internal/crypt"

	"github.com/spf13/cobra"
)

const (
	flagCost = "cost"
)

func buildGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "generate",
		Aliases:      []string{"g"},
		Short:        "Generate bcrypt hash",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cost, _ := cmd.Flags().GetInt(flagCost)

			bc, err := crypt.NewBcryptGenerator(cost)
			if err != nil {
				return err
			}

			password := args[0]
			hashed, err := bc.Generate(password)
			if err != nil {
				return err
			}

			fmt.Println(hashed)
			return nil
		},
	}

	cmd.Flags().IntP(flagCost, "c", bcrypt.DefaultCost, "Cost of bcrypt")

	return cmd
}
