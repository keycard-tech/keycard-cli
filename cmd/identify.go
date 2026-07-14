package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// IdentifyCommand returns the identify command (V1 only).
func IdentifyCommand() *cli.Command {
	return &cli.Command{
		Name:  "identify",
		Usage: "Identify the card (V1 only, verifies card genuinity)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "public-key",
				Usage: "Expected public key to verify against (hex)",
			},
		},
		Action: cmdIdentify,
	}
}

func cmdIdentify(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement identify
	return fmt.Errorf("identify: not implemented yet")
}
