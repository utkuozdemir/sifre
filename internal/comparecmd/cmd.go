package comparecmd

import (
	"bufio"
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/utkuozdemir/sifre/internal/crypt"
	"golang.org/x/term"
)

const (
	flagQuiet = "quiet"
)

func New(algorithmName string, comparer crypt.BidirectionalComparer) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "compare",
		Aliases:      []string{"c"},
		Short:        fmt.Sprintf("Compare password with %s hash", algorithmName),
		Args:         cobra.MaximumNArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			quiet, _ := cmd.Flags().GetBool(flagQuiet)
			cmd.SilenceErrors = quiet

			if quiet {
				null, _ := os.Open(os.DevNull)
				defer func() { _ = null.Close() }()
				os.Stdout = null
			}

			match, err := compare(comparer, args)
			if err != nil {
				return err
			}

			if !match {
				return fmt.Errorf("password and hash do not match")
			}

			fmt.Println("Matched!")
			return nil
		},
	}

	cmd.Flags().BoolP(flagQuiet, "q", false, "Do not write to stdout")
	return cmd
}

func compare(comparer crypt.BidirectionalComparer, args []string) (bool, error) {
	if len(args) == 1 {
		pwd, err := readStdin()
		if err != nil {
			return false, err
		}

		return comparer.Compare(pwd, args[0])
	}

	return comparer.CompareBidirectional(args[0], args[1])
}

func readStdin() (string, error) {
	stat, _ := os.Stdin.Stat()

	// data is piped
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		var stdin []byte
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			stdin = append(stdin, scanner.Bytes()...)
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return string(stdin), nil
	}

	fmt.Println("Password: ")
	pwd, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", err
	}
	return string(pwd), nil
}
