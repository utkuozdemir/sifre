package bcrypt

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:     "bcrypt",
	Aliases: []string{"b"},
	Short:   "Bcrypt related commands",
}
