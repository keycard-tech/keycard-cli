package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// PinlessCommands returns the pinless signing command group.
func PinlessCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "set-pinless-path",
			Usage: "Set the pinless signing path (applet < 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "path",
					Usage:    "Derivation path",
					Required: true,
				},
			},
			Action: cmdSetPinlessPath,
		},
		{
			Name:   "reset-pinless-path",
			Usage:  "Reset the pinless signing path (applet < 4.0 only)",
			Action: cmdResetPinlessPath,
		},
	}
}

func cmdSetPinlessPath(ctx context.Context, cmd *cli.Command) error {
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

	if internal.IsAppletV4Plus(kc) {
		return fmt.Errorf("pinless signing is not available on applet version 4.0+")
	}

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	path := cmd.String("path")
	if err := kc.SetPinlessPath(path); err != nil {
		return err
	}

	fmt.Printf("Pinless path set: %s\n", path)
	return nil
}

func cmdResetPinlessPath(ctx context.Context, cmd *cli.Command) error {
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

	if internal.IsAppletV4Plus(kc) {
		return fmt.Errorf("pinless signing is not available on applet version 4.0+")
	}

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	if err := kc.ResetPinlessPath(); err != nil {
		return err
	}

	fmt.Println("Pinless path reset")
	return nil
}
