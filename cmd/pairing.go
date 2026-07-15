package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// PairingCommands returns the pairing command group.
func PairingCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "pair",
			Usage: "Pair with the card (V1 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "pairing-password",
					Usage: "Pairing password (or KEYCARD_PAIRING_PASSWORD env var)",
				},
			},
			Action: cmdPair,
		},
		{
			Name:  "unpair",
			Usage: "Unpair from the card (V1 only)",
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:     "index",
					Usage:    "Pairing index to unpair",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "pairing-password",
					Usage: "Pairing password (or KEYCARD_PAIRING_PASSWORD env var)",
				},
			},
			Action: cmdUnpair,
		},
		{
			Name:   "unpair-others",
			Usage:  "Unpair all other pairings (V1 only)",
			Action: cmdUnpairOthers,
		},
		{
			Name:   "secure-channel-version",
			Usage:  "Show the secure channel version (V1 or V2)",
			Action: cmdSecureChannelVersion,
		},
	}
}

func cmdPair(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsSecureChannelV2(kc) {
			return fmt.Errorf("pairing is not needed for Secure Channel V2 cards")
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
		if internal.IsSecureChannelV2(kc) {
			return fmt.Errorf("unpair is not needed for Secure Channel V2 cards")
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
		if internal.IsSecureChannelV2(kc) {
			return fmt.Errorf("unpair-others is not needed for Secure Channel V2 cards")
		}

		if err := kc.UnpairOthers(); err != nil {
			return err
		}

		return PrintResultCLI(cmd, ActionResult{Message: "All other pairings removed"})
	})
}

func cmdSecureChannelVersion(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		version, err := doKeycardSecureChannelVersion(kc)
		if err != nil {
			return err
		}

		return PrintResultCLI(cmd, SecureChannelVersionResult{Version: version})
	})
}
