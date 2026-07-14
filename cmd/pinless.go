package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
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
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("pinless signing is not available on applet version 4.0+")
		}

		path := cmd.String("path")
		if err := kc.SetPinlessPath(path); err != nil {
			return err
		}

		fmt.Printf("Pinless path set: %s\n", path)
		return nil
	})
}

func cmdResetPinlessPath(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("pinless signing is not available on applet version 4.0+")
		}

		if err := kc.ResetPinlessPath(); err != nil {
			return err
		}

		fmt.Println("Pinless path reset")
		return nil
	})
}
