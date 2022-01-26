package bcrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/spf13/cobra"
)

const (
	flagCost = "cost"
)

var generateCmd = &cobra.Command{
	Use:          "generate",
	Aliases:      []string{"g"},
	Short:        "Generate bcrypt hash",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cost, err := cmd.Flags().GetInt(flagCost)
		if err != nil {
			return err
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(args[0]), cost)
		if err != nil {
			return err
		}

		fmt.Println(string(hashed))
		return nil
	},
}

func init() {
	Cmd.AddCommand(generateCmd)
	generateCmd.Flags().IntP(flagCost, "c", bcrypt.DefaultCost, "Cost of bcrypt")
}
