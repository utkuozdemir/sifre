package bcrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/spf13/cobra"
)

var costCmd = &cobra.Command{
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

		fmt.Println(cost)
		return nil
	},
}

func init() {
	Cmd.AddCommand(costCmd)
}
