package cmd

import (
	"fmt"
	"os"

	"github.com/utkuozdemir/sifre/cmd/argon2"

	"github.com/utkuozdemir/sifre/cmd/bcrypt"

	"github.com/spf13/cobra"
)

var (
	// will be overridden by goreleaser: https://goreleaser.com/cookbooks/using-main.version
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:     "sifre",
	Short:   "CLI tool for password related operations",
	Version: fmt.Sprintf("%s (commit: %s) (build date: %s)", version, commit, date),
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(bcrypt.Cmd)
	rootCmd.AddCommand(argon2.Cmd)
}
