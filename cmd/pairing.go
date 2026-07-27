package cmd

import (
	"context"
	"fmt"

	keycard "github.com/keycard-tech/keycard-go/v4"
	"github.com/urfave/cli/v3"

	"github.com/keycard-tech/keycard-cli/internal"
)

// PairingCommands returns the pairing command group.
func PairingCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "pair",
			Usage: "Pair with the card (applet < 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "pairing-password",
					Usage:   "Pairing password",
					Sources: cli.EnvVars("KEYCARD_PAIRING_PASSWORD"),
				},
			},
			Action: cmdPair,
		},
		{
			Name:  "unpair",
			Usage: "Unpair from the card (applet < 4.0 only)",
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:     "index",
					Usage:    "Pairing index to unpair",
					Required: true,
				},
				&cli.StringFlag{
					Name:    "pairing-password",
					Usage:   "Pairing password",
					Sources: cli.EnvVars("KEYCARD_PAIRING_PASSWORD"),
				},
			},
			Action: cmdUnpair,
		},
		{
			Name:   "unpair-all",
			Usage:  "Unpair all pairings (applet < 4.0 only)",
			Action: cmdUnpairOthers,
		},
	}
}

func cmdPair(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("pairing is not available on applet version 4.0+")
		}

		secrets := internal.ResolveSecrets("", "", cmd.String("pairing-password"))
		pairing, err := doKeycardPair(kc, secrets.PairingPass)
		if err != nil {
			return err
		}

		key := pairing.Key()
		return PrintResultCLI(cmd, PairingResult{
			PairingKey:   fmt.Sprintf("0x%x", key[:]),
			PairingIndex: int(pairing.Index()),
		})
	})
}

func cmdUnpair(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("unpair is not available on applet version 4.0+")
		}

		index := uint8(cmd.Int("index"))
		if err := kc.Unpair(index); err != nil {
			return err
		}

		return PrintResultCLI(cmd, UnpairResult{Index: int(index)})
	})
}

func cmdUnpairOthers(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("unpair-others is not available on applet version 4.0+")
		}

		if err := kc.UnpairOthers(); err != nil {
			return err
		}

		return PrintResultCLI(cmd, ActionResult{Message: "All other pairings removed"})
	})
}
