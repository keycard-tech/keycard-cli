package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
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

	if err := kc.Select(); err != nil {
		if e, ok := err.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
			// Applet not installed
		} else {
			return err
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

	info := kc.AppInfo()
	cashInfo := cashKC.CashApplicationInfo

	if cmd.Bool("json") {
		type infoOut struct {
			Keycard struct {
				Installed            bool     `json:"installed"`
				Initialized          bool     `json:"initialized"`
				AppVersion           string   `json:"app_version,omitempty"`
				AppVersionHex        string   `json:"app_version_hex,omitempty"`
				HasMasterKey         bool     `json:"has_master_key"`
				KeyUID               string   `json:"key_uid,omitempty"`
				SecureChannelVersion string   `json:"secure_channel_version,omitempty"`
				Capabilities         []string `json:"capabilities,omitempty"`
				PINRetries           int      `json:"pin_retries,omitempty"`
				LEEMode              bool     `json:"lee_mode"`
				HasFactoryResetCap   bool     `json:"has_factory_reset_capability"`
			} `json:"keycard"`
			Cash struct {
				Installed bool   `json:"installed"`
				PublicKey string `json:"public_key,omitempty"`
				Address   string `json:"address,omitempty"`
				Version   string `json:"version,omitempty"`
			} `json:"cash"`
		}

		out := infoOut{}
		if info != nil && info.Installed {
			out.Keycard.Installed = true
			out.Keycard.Initialized = info.Initialized
			out.Keycard.AppVersion = info.AppVersionString()
			out.Keycard.AppVersionHex = fmt.Sprintf("0x%04x", info.AppVersion())
			out.Keycard.LEEMode = info.IsLEEMode()
			out.Keycard.HasFactoryResetCap = info.HasFactoryResetCapability()
			if retries, ok := info.PINRetries(); ok {
				out.Keycard.PINRetries = int(retries)
			}
			if len(info.KeyUID) > 0 {
				out.Keycard.HasMasterKey = true
				out.Keycard.KeyUID = "0x" + hex.EncodeToString(info.KeyUID)
			}
			if ver, ok := kc.SecureChannelVersion(); ok {
				out.Keycard.SecureChannelVersion = fmt.Sprintf("v%d", ver+1)
			}
			if info.HasSecureChannelCapability() {
				out.Keycard.Capabilities = append(out.Keycard.Capabilities, "secure-channel")
			}
			if info.HasKeyManagementCapability() {
				out.Keycard.Capabilities = append(out.Keycard.Capabilities, "key-management")
			}
			if info.HasCredentialsManagementCapability() {
				out.Keycard.Capabilities = append(out.Keycard.Capabilities, "credentials-management")
			}
			if info.HasNDEFCapability() {
				out.Keycard.Capabilities = append(out.Keycard.Capabilities, "ndef")
			}
		}

		if cashInfo != nil && cashInfo.Installed {
			out.Cash.Installed = true
			out.Cash.PublicKey = "0x" + hex.EncodeToString(cashInfo.PublicKey)
			out.Cash.Version = "0x" + hex.EncodeToString(cashInfo.Version)
			if len(cashInfo.PublicKey) > 0 {
				if pubkey, err := crypto.UnmarshalPubkey(cashInfo.PublicKey); err == nil {
					out.Cash.Address = crypto.PubkeyToAddress(*pubkey).Hex()
				}
			}
		}

		return internal.PrintJSON(out)
	}

	// Human-readable output
	fmt.Println("Keycard Applet:")
	if info == nil || !info.Installed {
		fmt.Println("  Installed: false")
	} else {
		fmt.Printf("  Installed: true\n")
		fmt.Printf("  Initialized: %v\n", info.Initialized)
		fmt.Printf("  App Version: %s (0x%04x)\n", info.AppVersionString(), info.AppVersion())
		fmt.Printf("  LEE Mode: %v\n", info.IsLEEMode())
		fmt.Printf("  Key Initialized: %v\n", len(info.KeyUID) > 0)
		if len(info.KeyUID) > 0 {
			fmt.Printf("  Key UID: 0x%x\n", info.KeyUID)
		}
		fmt.Printf("  Capabilities:\n")
		fmt.Printf("    Secure channel: %v\n", info.HasSecureChannelCapability())
		fmt.Printf("    Key management: %v\n", info.HasKeyManagementCapability())
		fmt.Printf("    Credentials Management: %v\n", info.HasCredentialsManagementCapability())
		fmt.Printf("    NDEF: %v\n", info.HasNDEFCapability())
		fmt.Printf("    Factory reset: %v\n", info.HasFactoryResetCapability())
	}

	fmt.Println("Cash Applet:")
	if cashInfo == nil || !cashInfo.Installed {
		fmt.Println("  Installed: false")
		return nil
	}

	fmt.Printf("  Installed: true\n")
	fmt.Printf("  PublicKey: 0x%x\n", cashInfo.PublicKey)
	if len(cashInfo.PublicKey) > 0 {
		if pubkey, err := crypto.UnmarshalPubkey(cashInfo.PublicKey); err == nil {
			fmt.Printf("  Address: %s\n", crypto.PubkeyToAddress(*pubkey).Hex())
		}
	}
	fmt.Printf("  Version: 0x%x\n", cashInfo.Version)

	return nil
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
		// TODO: interactive confirmation
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
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)

	if err := kc.Select(); err != nil {
		return err
	}

	info := kc.AppInfo()
	if !info.Installed {
		return fmt.Errorf("keycard applet not installed. Run 'keycard install' first")
	}
	if info.Initialized {
		return fmt.Errorf("card already initialized")
	}

	// Resolve secrets
	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)

	// Generate if not provided
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
		// Use InitWithOptions
		initErr = kc.InitWithOptions(
			secrets.Pin,
			cmd.String("alt-pin"),
			secrets.Puk,
			secrets.PairingPass,
			uint8(cmd.Uint("pin-retries")),
			uint8(cmd.Uint("puk-retries")),
		)
	} else if v2 {
		initErr = kc.InitV2(secrets.Pin, secrets.Puk)
	} else {
		initErr = kc.Init(keycard.NewSecrets(secrets.Pin, secrets.Puk, secrets.PairingPass))
	}

	if initErr != nil {
		return initErr
	}

	fmt.Println("Card initialized.")
	fmt.Printf("PIN: %s\n", secrets.Pin)
	fmt.Printf("PUK: %s\n", secrets.Puk)
	if !internal.IsSecureChannelV2(kc) {
		fmt.Printf("Pairing password: %s\n", secrets.PairingPass)
	}
	return nil
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

	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)

	if err := kc.Select(); err != nil {
		return err
	}

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
}
