package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// CredentialsCommands returns the credentials management command group.
func CredentialsCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "verify-pin",
			Usage:  "Verify the PIN",
			Action: cmdVerifyPIN,
		},
		{
			Name:  "change-pin",
			Usage: "Change the PIN",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "new",
					Usage:    "New PIN",
					Required: true,
				},
			},
			Action: cmdChangePIN,
		},
		{
			Name:  "change-puk",
			Usage: "Change the PUK",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "new",
					Usage:    "New PUK",
					Required: true,
				},
			},
			Action: cmdChangePUK,
		},
		{
			Name:  "unblock-pin",
			Usage: "Unblock the PIN using the PUK",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "puk",
					Usage:    "PUK (or KEYCARD_PUK env var)",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "new-pin",
					Usage:    "New PIN",
					Required: true,
				},
			},
			Action: cmdUnblockPIN,
		},
		{
			Name:  "change-pairing-password",
			Usage: "Change the pairing password (V1 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "new",
					Usage:    "New pairing password",
					Required: true,
				},
			},
			Action: cmdChangePairingPassword,
		},
	}
}

func cmdVerifyPIN(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement verify-pin
	return fmt.Errorf("verify-pin: not implemented yet")
}

func cmdChangePIN(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement change-pin
	return fmt.Errorf("change-pin: not implemented yet")
}

func cmdChangePUK(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement change-puk
	return fmt.Errorf("change-puk: not implemented yet")
}

func cmdUnblockPIN(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement unblock-pin
	return fmt.Errorf("unblock-pin: not implemented yet")
}

func cmdChangePairingPassword(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement change-pairing-password
	return fmt.Errorf("change-pairing-password: not implemented yet")
}
