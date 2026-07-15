package cmd

import (
	"context"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"
)

// MetadataCommands returns the metadata management command group.
func MetadataCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "get-name",
			Usage:  "Get the card's display name",
			Action: cmdGetName,
		},
		{
			Name:  "set-name",
			Usage: "Set the card's display name",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "name",
					Usage:    "Display name for the card",
					Required: true,
				},
			},
			Action: cmdSetName,
		},
	}
}

func cmdGetName(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		name, err := doKeycardGetName(kc)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, NameResult{Name: name})
	})
}

func cmdSetName(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		name := cmd.String("name")
		if err := doKeycardSetName(kc, name); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Card name set: " + name})
	})
}
