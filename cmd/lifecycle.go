package cmd

import (
	"context"
	"fmt"
	"os"

	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// LifecycleCommands returns the lifecycle command group (version, info, install, delete, init, factory-reset).
func LifecycleCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "version",
			Usage:  "Show version information",
			Action: cmdVersion,
		},
		{
			Name:   "info",
			Usage:  "Show card information",
			Action: cmdInfo,
		},
		{
			Name:  "install",
			Usage: "Install applets to the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "applet-file",
					Aliases:  []string{"a"},
					Usage:    "applet cap file path",
					Required: true,
				},
				&cli.BoolFlag{
					Name:  "keycard-applet",
					Usage: "install keycard applet",
					Value: true,
				},
				&cli.BoolFlag{
					Name:  "cash-applet",
					Usage: "install cash applet",
					Value: true,
				},
				&cli.BoolFlag{
					Name:  "ndef-applet",
					Usage: "install NDEF applet",
					Value: true,
				},
				&cli.BoolFlag{
					Name:    "force",
					Aliases: []string{"f"},
					Usage:   "force applet installation if already installed",
				},
				&cli.StringFlag{
					Name:  "ndef",
					Usage: "Specify a URL to use in the NDEF record. Use {{.cashAddress}} variable for cash address.",
				},
			},
			Action: cmdInstall,
		},
		{
			Name:  "delete",
			Usage: "Delete applets from the card",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "yes",
					Aliases: []string{"y"},
					Usage:   "skip confirmation",
				},
			},
			Action: cmdDelete,
		},
		{
			Name:  "init",
			Usage: "Initialize the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "pin",
					Usage: "PIN (or KEYCARD_PIN env var)",
				},
				&cli.StringFlag{
					Name:  "puk",
					Usage: "PUK (or KEYCARD_PUK env var)",
				},
				&cli.StringFlag{
					Name:  "pairing-password",
					Usage: "Pairing password (V1 only, or KEYCARD_PAIRING_PASSWORD env var)",
				},
				&cli.StringFlag{
					Name:  "alt-pin",
					Usage: "Alternative PIN",
				},
				&cli.UintFlag{
					Name:  "pin-retries",
					Usage: "Number of PIN retries allowed",
				},
				&cli.UintFlag{
					Name:  "puk-retries",
					Usage: "Number of PUK retries allowed",
				},
			},
			Action: cmdInit,
		},
		{
			Name:  "factory-reset",
			Usage: "Factory reset the card",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "yes",
					Aliases: []string{"y"},
					Usage:   "skip confirmation",
				},
			},
			Action: cmdFactoryReset,
		},
	}
}

func cmdVersion(ctx context.Context, cmd *cli.Command) error {
	fmt.Printf("keycard version %s\n", "dev")
	return nil
}

func cmdInfo(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)

	var selectErr error
	if selectErr = kc.Select(); selectErr != nil {
		if e, ok := selectErr.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
			// Applet not installed
		} else {
			if kc.AppInfo() == nil || !kc.AppInfo().Installed {
				return selectErr
			}
		}
	}

	cashKC := keycard.NewCashCommandSet(ch)
	if err := cashKC.Select(); err != nil {
		if e, ok := err.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
			// Cash not installed
		} else {
			return err
		}
	}

	result, err := doKeycardInfo(kc, cashKC, selectErr)
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(result)
	}

	formatKeycardInfoStdout(result)
	return nil
}

func formatKeycardInfoStdout(result *KeycardInfoResult) {
	kc := result.Keycard
	fmt.Println("Keycard Applet:")
	if !kc.Installed {
		fmt.Println("  Installed: false")
	} else {
		fmt.Println("  Installed: true")
		fmt.Printf("  Initialized: %v\n", kc.Initialized)
		fmt.Printf("  App Version: %s (%s)\n", kc.AppVersion, kc.AppVersionHex)
		fmt.Printf("  LEE Mode: %v\n", kc.LEEMode)
		fmt.Printf("  Key Initialized: %v\n", kc.HasMasterKey)
		if kc.KeyUID != "" {
			fmt.Printf("  Key UID: %s\n", kc.KeyUID)
		}
		fmt.Println("  Capabilities:")
		for _, cap := range kc.Capabilities {
			fmt.Printf("    %s\n", cap)
		}
		if kc.InstanceUID != "" {
			fmt.Printf("  Instance UID: %s\n", kc.InstanceUID)
		}
		if kc.AvailableSlots != nil {
			fmt.Printf("  Available pairing slots: %d\n", *kc.AvailableSlots)
		}
		if kc.Certificate != "" {
			fmt.Printf("  Certificate: %s\n", kc.Certificate)
			if kc.IdentityPubKey != "" {
				fmt.Printf("  Identity public key: %s\n", kc.IdentityPubKey)
			}
		}
		if kc.CertVerification != "" {
			fmt.Printf("  Certificate verification error: %s\n", kc.CertVerification)
		}
	}

	fmt.Println("Cash Applet:")
	cash := result.Cash
	if !cash.Installed {
		fmt.Println("  Installed: false")
		return
	}
	fmt.Println("  Installed: true")
	fmt.Printf("  PublicKey: %s\n", cash.PublicKey)
	if cash.Address != "" {
		fmt.Printf("  Address: %s\n", cash.Address)
	}
	fmt.Printf("  Version: %s\n", cash.Version)
}

func cmdInstall(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	capFile := cmd.String("applet-file")
	f, err := os.Open(capFile)
	if err != nil {
		return fmt.Errorf("error opening cap file: %w", err)
	}
	defer f.Close()

	i := internal.NewInstaller(card)
	return i.Install(f, cmd.Bool("force"), cmd.Bool("keycard-applet"), cmd.Bool("cash-applet"), cmd.Bool("ndef-applet"), cmd.String("ndef"))
}

func cmdDelete(ctx context.Context, cmd *cli.Command) error {
	if !cmd.Bool("yes") {
		fmt.Print("This will delete all applets from the card. Continue? (y/N): ")
		var resp string
		fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			return nil
		}
	}

	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	i := internal.NewInstaller(card)
	if err := i.Delete(); err != nil {
		return err
	}

	fmt.Println("Applets deleted")
	return nil
}

func cmdInit(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		info := kc.AppInfo()
		if !info.Installed {
			return fmt.Errorf("keycard applet not installed. Run 'keycard install' first")
		}
		if info.Initialized {
			return fmt.Errorf("card already initialized")
		}

		secrets := internal.ResolveSecrets(
			cmd.String("pin"),
			cmd.String("puk"),
			cmd.String("pairing-password"),
		)

		if secrets.Pin == "" || secrets.Puk == "" {
			genSecrets, err := keycard.GenerateSecrets()
			if err != nil {
				return err
			}
			if secrets.Pin == "" {
				secrets.Pin = genSecrets.Pin()
			}
			if secrets.Puk == "" {
				secrets.Puk = genSecrets.Puk()
			}
			if secrets.PairingPass == "" {
				secrets.PairingPass = genSecrets.PairingPass()
			}
		}

		v2 := internal.IsSecureChannelV2(kc)
		var initErr error

		if cmd.IsSet("alt-pin") || cmd.IsSet("pin-retries") || cmd.IsSet("puk-retries") {
			initErr = kc.InitWithOptions(
				secrets.Pin,
				cmd.String("alt-pin"),
				secrets.Puk,
				secrets.PairingPass,
				uint8(cmd.Uint("pin-retries")),
				uint8(cmd.Uint("puk-retries")),
			)
		} else {
			kcSecrets := keycard.NewSecrets(secrets.Pin, secrets.Puk, secrets.PairingPass)
			initErr = doKeycardInit(kc, kcSecrets)
		}

		if initErr != nil {
			return initErr
		}

		fmt.Println("Card initialized.")
		fmt.Printf("PIN: %s\n", secrets.Pin)
		fmt.Printf("PUK: %s\n", secrets.Puk)
		if !v2 {
			fmt.Printf("Pairing password: %s\n", secrets.PairingPass)
		}
		return nil
	})
}

func cmdFactoryReset(ctx context.Context, cmd *cli.Command) error {
	if !cmd.Bool("yes") {
		fmt.Print("This will factory reset the card. All data will be lost. Continue? (y/N): ")
		var resp string
		fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			return nil
		}
	}

	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		info := kc.AppInfo()
		if !info.Installed {
			return fmt.Errorf("keycard applet not installed")
		}
		if !info.HasFactoryResetCapability() {
			return fmt.Errorf("card does not support factory reset")
		}

		if err := kc.FactoryReset(); err != nil {
			return err
		}

		fmt.Println("Card factory reset complete")
		return nil
	})
}
