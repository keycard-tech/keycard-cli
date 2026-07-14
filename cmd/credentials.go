package cmd

import (
	"context"
	"fmt"
	"os"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
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
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		fmt.Println("PIN verified successfully")
		return nil
	})
}

func cmdChangePIN(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.ChangePIN(cmd.String("new")); err != nil {
			return err
		}
		fmt.Println("PIN changed successfully")
		return nil
	})
}

func cmdChangePUK(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.ChangePUK(cmd.String("new")); err != nil {
			return err
		}
		fmt.Println("PUK changed successfully")
		return nil
	})
}

func cmdUnblockPIN(ctx context.Context, cmd *cli.Command) error {
	puk := cmd.String("puk")
	if puk == "" {
		if v := os.Getenv("KEYCARD_PUK"); v != "" {
			puk = v
		}
	}
	newPIN := cmd.String("new-pin")

	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		// UnblockPIN needs secure channel open but not PIN verified.
		secrets := internal.ResolveSecrets("", "", cmd.String("pairing-password"))

		if !internal.IsSecureChannelV2(kc) && secrets.PairingPass != "" {
			if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret(secrets.PairingPass)); err != nil {
				return err
			}
		}
		if err := kc.AutoOpenSecureChannel(); err != nil {
			return err
		}
		defer internal.AutoUnpair(kc)

		if err := kc.UnblockPIN(puk, newPIN); err != nil {
			return err
		}
		fmt.Println("PIN unblocked successfully")
		return nil
	})
}

func cmdChangePairingPassword(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsSecureChannelV2(kc) {
			return fmt.Errorf("pairing password change is not applicable for Secure Channel V2 cards")
		}
		if err := kc.ChangePairingPassword(cmd.String("new")); err != nil {
			return err
		}
		fmt.Println("Pairing password changed successfully")
		return nil
	})
}
