package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
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

		if cmd.Bool("json") {
			return internal.PrintJSON(NameResult{Name: name})
		}

		fmt.Printf("Card name: %s\n", name)
		return nil
	})
}

func cmdSetName(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := doKeycardSetName(kc, cmd.String("name")); err != nil {
			return err
		}

		fmt.Printf("Card name set: %s\n", cmd.String("name"))
		return nil
	})
}
