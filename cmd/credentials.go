package cmd

import (
	"context"
	"fmt"

	keycard "github.com/keycard-tech/keycard-go/v4"
	"github.com/urfave/cli/v3"

	"github.com/keycard-tech/keycard-cli/internal"
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
					Sources:  cli.EnvVars("KEYCARD_NEW_PIN"),
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
					Sources:  cli.EnvVars("KEYCARD_NEW_PUK"),
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
					Name:    "puk",
					Usage:   "PUK",
					Sources: cli.EnvVars("KEYCARD_PUK"),
				},
				&cli.StringFlag{
					Name:     "new-pin",
					Usage:    "New PIN",
					Sources:  cli.EnvVars("KEYCARD_NEW_PIN"),
					Required: true,
				},
			},
			Action: cmdUnblockPIN,
		},
		{
			Name:  "change-pairing-password",
			Usage: "Change the pairing password (applet < 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "new",
					Usage:    "New pairing password",
					Sources:  cli.EnvVars("KEYCARD_NEW_PAIRING_PASSWORD"),
					Required: true,
				},
			},
			Action: cmdChangePairingPassword,
		},
	}
}

func cmdVerifyPIN(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		return PrintResultCLI(cmd, ActionResult{Message: "PIN verified successfully"})
	})
}

func cmdChangePIN(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.ChangePIN(cmd.String("new")); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "PIN changed successfully"})
	})
}

func cmdChangePUK(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.ChangePUK(cmd.String("new")); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "PUK changed successfully"})
	})
}

func cmdUnblockPIN(ctx context.Context, cmd *cli.Command) error {
	puk := cmd.String("puk")
	newPIN := cmd.String("new-pin")

	return runCard(cmd, AuthSecureChannel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.UnblockPIN(puk, newPIN); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "PIN unblocked successfully"})
	})
}

func cmdChangePairingPassword(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("change-pairing-password is not available on applet version 4.0+")
		}
		if err := kc.ChangePairingPassword(cmd.String("new")); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Pairing password changed successfully"})
	})
}
