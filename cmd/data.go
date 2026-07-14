package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// DataCommands returns the data management command group.
func DataCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "get-data",
			Usage: "Get data from the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "type",
					Usage:    "Data type: public, ndef, or cash",
					Required: true,
				},
			},
			Action: cmdGetData,
		},
		{
			Name:  "store-data",
			Usage: "Store data on the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "type",
					Usage:    "Data type: public, ndef, or cash",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "hex",
					Usage: "Data as hex string",
				},
				&cli.StringFlag{
					Name:  "file",
					Usage: "Path to file containing data",
				},
			},
			Action: cmdStoreData,
		},
		{
			Name:  "get-challenge",
			Usage: "Get a random challenge from the card",
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:     "length",
					Usage:    "Challenge length in bytes",
					Required: true,
				},
			},
			Action: cmdGetChallenge,
		},
		{
			Name:  "set-ndef",
			Usage: "Set the NDEF record on the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hex",
					Usage: "NDEF data as hex string",
				},
				&cli.StringFlag{
					Name:  "file",
					Usage: "Path to NDEF file",
				},
			},
			Action: cmdSetNDEF,
		},
		{
			Name:   "get-status",
			Usage:  "Get card status (PIN retries, key path, etc.)",
			Action: cmdGetStatus,
		},
	}
}

func cmdGetData(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement get-data
	return fmt.Errorf("get-data: not implemented yet")
}

func cmdStoreData(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement store-data
	return fmt.Errorf("store-data: not implemented yet")
}

func cmdGetChallenge(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement get-challenge
	return fmt.Errorf("get-challenge: not implemented yet")
}

func cmdSetNDEF(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement set-ndef
	return fmt.Errorf("set-ndef: not implemented yet")
}

func cmdGetStatus(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement get-status
	return fmt.Errorf("get-status: not implemented yet")
}
