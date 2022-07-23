package bcryptcmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

func buildCostCmd() *cobra.Command {
	return &cobra.Command{ //nolint:exhaustruct
		Use:          "cost",
		Short:        "Return the cost of a bcrypt hash",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			hashed := []byte(args[0])

			cost, err := bcrypt.Cost(hashed)
			if err != nil {
				return err
			}

			fmt.Println(cost) //nolint:forbidigo

			return nil
		},
	}
}
