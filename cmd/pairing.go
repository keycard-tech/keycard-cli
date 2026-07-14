package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	keycardio "github.com/status-im/keycard-go/io"
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
	// TODO: implement pair
	return fmt.Errorf("pair: not implemented yet")
}

func cmdUnpair(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement unpair
	return fmt.Errorf("unpair: not implemented yet")
}

func cmdUnpairOthers(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement unpair-others
	return fmt.Errorf("unpair-others: not implemented yet")
}

func cmdSecureChannelVersion(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)

	if err := kc.Select(); err != nil {
		return err
	}

	ver, ok := kc.SecureChannelVersion()
	if !ok {
		return fmt.Errorf("could not determine secure channel version")
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"secure_channel_version": fmt.Sprintf("v%d", ver+1),
		})
	}

	fmt.Printf("Secure channel version: V%d\n", ver+1)
	return nil
}
