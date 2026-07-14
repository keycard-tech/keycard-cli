package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
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
	// TODO: implement cash-sign
	return fmt.Errorf("cash-sign: not implemented yet")
}
