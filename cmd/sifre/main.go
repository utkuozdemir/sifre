package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/utkuozdemir/sifre/internal/argon2cmd"
	"github.com/utkuozdemir/sifre/internal/bcryptcmd"
	"github.com/utkuozdemir/sifre/internal/completioncmd"
)

//nolint:gochecknoglobals
var (
	// will be overridden by goreleaser: https://goreleaser.com/cookbooks/using-main.version
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	rootCmd, err := buildRootCmd()
	if err != nil {
		fmt.Println(err) //nolint:forbidigo
		os.Exit(1)
	}

	err = rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func buildRootCmd() (*cobra.Command, error) {
	rootCmd := &cobra.Command{ //nolint:exhaustruct
		Use:     "sifre",
		Short:   "CLI tool for password related operations",
		Version: fmt.Sprintf("%s (commit: %s) (build date: %s)", version, commit, date),
	}

	a2cmd, err := argon2cmd.Build()
	if err != nil {
		return nil, err
	}

	bccmd, err := bcryptcmd.Build()
	if err != nil {
		return nil, err
	}

	name := rootCmd.Name()
	cmplcmd := completioncmd.Build(name)

	rootCmd.AddCommand(a2cmd)
	rootCmd.AddCommand(bccmd)
	rootCmd.AddCommand(cmplcmd)

	return rootCmd, nil
}
