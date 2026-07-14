package cmd

import (
	"context"
	"fmt"

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
	// TODO: implement get-name
	return fmt.Errorf("get-name: not implemented yet")
}

func cmdSetName(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement set-name
	return fmt.Errorf("set-name: not implemented yet")
}
