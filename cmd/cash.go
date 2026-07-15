package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// CashCommand returns the cash applet command group.
func CashCommand() *cli.Command {
	return &cli.Command{
		Name:  "cash-sign",
		Usage: "Sign with the Cash applet",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "hex",
				Usage:    "Data to sign as hex (32 bytes)",
				Required: true,
			},
		},
		Action: cmdCashSign,
	}
}

func cmdCashSign(ctx context.Context, cmd *cli.Command) error {
	data, err := internal.ParseHex(cmd.String("hex"))
	if err != nil {
		return fmt.Errorf("invalid hex data: %w", err)
	}

	return runCash(cmd, func(cashKC *keycard.CashCommandSet, _ *cli.Command) error {
		sig, err := doCashSign(cashKC, data)
		if err != nil {
			return err
		}
		return outputSignature(cmd, sig)
	})
}
