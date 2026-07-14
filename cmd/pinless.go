package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
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
	// TODO: implement set-pinless-path
	return fmt.Errorf("set-pinless-path: not implemented yet")
}

func cmdResetPinlessPath(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement reset-pinless-path
	return fmt.Errorf("reset-pinless-path: not implemented yet")
}
