package argon2cmd

import (
	"github.com/spf13/cobra"
	"github.com/utkuozdemir/sifre/internal/comparecmd"
	"github.com/utkuozdemir/sifre/internal/crypt"
)

func Build() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "argon2",
		Short: "Argon2 related commands",
	}

	comparer, err := crypt.NewArgon2Comparer()
	if err != nil {
		return nil, err
	}

	cmd.AddCommand(buildGenerateCmd())
	cmd.AddCommand(comparecmd.New("argon2", comparer))
	return cmd, nil
}
