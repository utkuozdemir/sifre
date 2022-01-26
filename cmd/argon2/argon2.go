package argon2

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:     "argon2",
	Aliases: []string{"a"},
	Short:   "Argon2 related commands",
}
