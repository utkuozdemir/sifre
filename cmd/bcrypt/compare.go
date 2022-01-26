package bcrypt

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/spf13/cobra"
)

const (
	flagQuiet = "quiet"
)

var compareCmd = &cobra.Command{
	Use:          "compare",
	Aliases:      []string{"c"},
	Short:        "Compare password with bcrypt hash",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		quiet, err := cmd.Flags().GetBool(flagQuiet)
		if err != nil {
			return err
		}

		arg1 := []byte(args[0])
		arg2 := []byte(args[1])

		err1 := bcrypt.CompareHashAndPassword(arg1, arg2)
		if err1 == nil {
			if !quiet {
				fmt.Println("Matched!")
			}
			return nil
		}

		err2 := bcrypt.CompareHashAndPassword(arg2, arg1)
		if err2 == nil {
			if !quiet {
				fmt.Println("Matched!")
			}
			return nil
		}

		if errors.Is(err1, bcrypt.ErrMismatchedHashAndPassword) {
			return err1
		}

		if errors.Is(err2, bcrypt.ErrMismatchedHashAndPassword) {
			return err2
		}

		if err1 != nil {
			return err1
		}

		return err2
	},
}

func init() {
	Cmd.AddCommand(compareCmd)
	compareCmd.Flags().BoolP(flagQuiet, "q", false, "Do not write to stdout")
}
