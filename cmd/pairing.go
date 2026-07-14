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

	if internal.IsSecureChannelV2(kc) {
		return fmt.Errorf("pairing is not needed for Secure Channel V2 cards")
	}

	pairingPass := cmd.String("pairing-password")
	if pairingPass == "" {
		if secrets, err := internal.ResolveSecrets("", "", "", cmd.String("secrets-file"), false); err == nil && secrets.PairingPass != "" {
			pairingPass = secrets.PairingPass
		}
	}
	if pairingPass == "" {
		pairingPass = "KeycardDefaultPairing"
	}

	if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret(pairingPass)); err != nil {
		return err
	}

	pairing := kc.Pairing()
	if pairing == nil {
		return fmt.Errorf("pairing succeeded but pairing info is nil")
	}

	key := pairing.Key()

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]interface{}{
			"pairing_key":   fmt.Sprintf("0x%x", key[:]),
			"pairing_index": pairing.Index(),
		})
	}

	fmt.Printf("Pairing key: 0x%x\n", key[:])
	fmt.Printf("Pairing index: %d\n", pairing.Index())
	return nil
}

func cmdUnpair(ctx context.Context, cmd *cli.Command) error {
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

	if internal.IsSecureChannelV2(kc) {
		return fmt.Errorf("unpair is not needed for Secure Channel V2 cards")
	}

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}

	index := uint8(cmd.Int("index"))
	if err := kc.Unpair(index); err != nil {
		return err
	}

	fmt.Printf("Unpaired (index: %d)\n", index)
	return nil
}

func cmdUnpairOthers(ctx context.Context, cmd *cli.Command) error {
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

	if internal.IsSecureChannelV2(kc) {
		return fmt.Errorf("unpair-others is not needed for Secure Channel V2 cards")
	}

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}

	if err := kc.UnpairOthers(); err != nil {
		return err
	}

	fmt.Println("All other pairings removed")
	return nil
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
