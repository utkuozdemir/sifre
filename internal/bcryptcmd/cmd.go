package bcryptcmd

import (
	"github.com/spf13/cobra"
	"github.com/utkuozdemir/sifre/internal/comparecmd"
	"github.com/utkuozdemir/sifre/internal/crypt"
)

func Build() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "bcrypt",
		Short: "Bcrypt related commands",
	}

	comparer, err := crypt.NewBcryptComparer()
	if err != nil {
		return nil, err
	}

	cmd.AddCommand(buildCostCmd())
	cmd.AddCommand(buildGenerateCmd())
	cmd.AddCommand(comparecmd.New("bcrypt", comparer))
	return cmd, nil
}
