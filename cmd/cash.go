package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// CashCommands returns the cash applet command group.
func CashCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "cash-info",
			Usage:  "Show Cash applet information",
			Action: cmdCashInfo,
		},
		{
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
		},
	}
}

func cmdCashInfo(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	cashKC := keycard.NewCashCommandSet(ch)

	if err := cashKC.Select(); err != nil {
		if e, ok := err.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
			// Cash not installed
		} else {
			return err
		}
	}

	result, err := doKeycardInfoCash(cashKC)
	if err != nil {
		return err
	}

	return PrintResultCLI(cmd, result)
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
		return PrintResultCLI(cmd, newSignatureResult(sig))
	})
}
