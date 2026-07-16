package cmd

import (
	"context"
	"encoding/hex"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// KeyCommands returns the key management command group.
func KeyCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "generate-key",
			Usage:  "Generate a new key on the card",
			Action: cmdGenerateKey,
		},
		{
			Name:   "remove-key",
			Usage:  "Remove the current key from the card",
			Action: cmdRemoveKey,
		},
		{
			Name:  "derive-key",
			Usage: "Derive a key at the given path (applet < 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "path",
					Usage:    "Derivation path (e.g. m/44'/60'/0'/0/0)",
					Required: true,
				},
			},
			Action: cmdDeriveKey,
		},
		{
			Name:  "load-seed",
			Usage: "Load a BIP39 seed onto the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hex",
					Usage: "Seed as hex string",
				},
				&cli.StringFlag{
					Name:  "mnemonic",
					Usage: "BIP39 mnemonic phrase",
				},
			},
			Action: cmdLoadSeed,
		},
		{
			Name:  "load-lee-seed",
			Usage: "Load a LEE seed onto the card (applet >= 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hex",
					Usage: "Seed as hex string",
				},
				&cli.StringFlag{
					Name:  "mnemonic",
					Usage: "BIP39 mnemonic phrase",
				},
			},
			Action: cmdLoadLEESeed,
		},
		{
			Name:  "export-public-key",
			Usage: "Export the public key",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "path",
					Usage: "Derivation path (optional)",
				},
				&cli.BoolFlag{
					Name:  "current",
					Usage: "Export the current key",
				},
			},
			Action: cmdExportPublicKey,
		},
		{
			Name:  "export-private-key",
			Usage: "Export the private key",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "path",
					Usage: "Derivation path (optional)",
				},
				&cli.BoolFlag{
					Name:  "current",
					Usage: "Export the current key",
				},
			},
			Action: cmdExportPrivateKey,
		},
		{
			Name:  "export-extended-key",
			Usage: "Export the extended key (public key + chain code)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "path",
					Usage: "Derivation path (optional)",
				},
				&cli.BoolFlag{
					Name:  "current",
					Usage: "Export the current key",
				},
			},
			Action: cmdExportExtendedKey,
		},
		{
			Name:  "export-lee-key",
			Usage: "Export a LEE key at the given path (applet >= 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "path",
					Usage:    "Derivation path",
					Required: true,
				},
			},
			Action: cmdExportLEEKey,
		},
		{
			Name:  "export-bip85",
			Usage: "Export a BIP85 derived key (applet >= 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "path",
					Usage:    "Derivation path",
					Required: true,
				},
				&cli.IntFlag{
					Name:  "length",
					Usage: "Key length in bytes",
					Value: 64,
				},
			},
			Action: cmdExportBIP85,
		},
	}
}

func cmdGenerateKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		keyUID, err := doKeycardGenerateKey(kc)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, KeyGenerateResult{
			KeyUID: "0x" + hex.EncodeToString(keyUID),
		})
	})
}

func cmdRemoveKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.RemoveKey(); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Key removed"})
	})
}

func cmdDeriveKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("derive-key is not available on applet version 4.0+")
		}
		path := cmd.String("path")
		if err := kc.DeriveKey(path); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Key derived at path: " + path})
	})
}

func cmdLoadSeed(ctx context.Context, cmd *cli.Command) error {
	mnemonic := cmd.String("mnemonic")
	seedHex := cmd.String("hex")

	if mnemonic != "" && seedHex != "" {
		return fmt.Errorf("cannot specify both --mnemonic and --hex")
	}
	if mnemonic == "" && seedHex == "" {
		return fmt.Errorf("must specify either --mnemonic or --hex")
	}

	var seed []byte
	if mnemonic != "" {
		if err := types.ValidateMnemonic(mnemonic); err != nil {
			return fmt.Errorf("invalid BIP39 mnemonic: %w", err)
		}
		seed = types.BinarySeedFromPhrase(mnemonic, "")
	} else {
		var err error
		seed, err = internal.ParseHex(seedHex)
		if err != nil {
			return fmt.Errorf("invalid hex seed: %w", err)
		}
	}

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		keyID, err := kc.LoadSeed(seed)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, KeyLoadResult{
			KeyID: "0x" + hex.EncodeToString(keyID),
		})
	})
}

func cmdLoadLEESeed(ctx context.Context, cmd *cli.Command) error {
	mnemonic := cmd.String("mnemonic")
	seedHex := cmd.String("hex")

	if mnemonic != "" && seedHex != "" {
		return fmt.Errorf("cannot specify both --mnemonic and --hex")
	}
	if mnemonic == "" && seedHex == "" {
		return fmt.Errorf("must specify either --mnemonic or --hex")
	}

	var seed []byte
	if mnemonic != "" {
		if err := types.ValidateMnemonic(mnemonic); err != nil {
			return fmt.Errorf("invalid BIP39 mnemonic: %w", err)
		}
		seed = types.BinarySeedFromPhrase(mnemonic, "")
	} else {
		var err error
		seed, err = internal.ParseHex(seedHex)
		if err != nil {
			return fmt.Errorf("invalid hex seed: %w", err)
		}
	}

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if !internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("load-lee-seed is only available on applet version 4.0+")
		}
		if err := kc.LoadLEEKey(seed); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "LEE seed loaded"})
	})
}

func cmdExportPublicKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) && cmd.String("path") == "" {
			return fmt.Errorf("--path is required for applet version 4.0+")
		}
		exported, err := doKeycardExportKey(kc, cmd.String("path"), cmd.Bool("current"), keycard.P2ExportKeyPublicOnly)
		if err != nil {
			return err
		}
		result := doKeycardExportKeyResult(exported, false, cmd.String("path"))
		return PrintResultCLI(cmd, result)
	})
}

func cmdExportPrivateKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) && cmd.String("path") == "" {
			return fmt.Errorf("--path is required for applet version 4.0+")
		}
		exported, err := doKeycardExportKey(kc, cmd.String("path"), cmd.Bool("current"), keycard.P2ExportKeyPrivateAndPublic)
		if err != nil {
			return err
		}
		result := doKeycardExportKeyResult(exported, true, cmd.String("path"))
		return PrintResultCLI(cmd, result)
	})
}

func cmdExportExtendedKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) && cmd.String("path") == "" {
			return fmt.Errorf("--path is required for applet version 4.0+")
		}
		exported, err := doKeycardExportKey(kc, cmd.String("path"), cmd.Bool("current"), keycard.P2ExportKeyExtendedPublic)
		if err != nil {
			return err
		}
		result := doKeycardExportExtendedKeyResult(exported, cmd.String("path"))
		return PrintResultCLI(cmd, result)
	})
}

func cmdExportLEEKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if !internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("export-lee-key is only available on applet version 4.0+")
		}
		path := cmd.String("path")
		key, err := kc.ExportLEEKey(path)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, LEEKeyResult{
			Key:  "0x" + hex.EncodeToString(key),
			Path: path,
		})
	})
}

func cmdExportBIP85(ctx context.Context, cmd *cli.Command) error {
	path := cmd.String("path")
	length := uint8(cmd.Int("length"))

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if !internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("export-bip85 is only available on applet version 4.0+")
		}
		key, err := kc.ExportBIP85(path, length)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, BIP85KeyResult{
			Key:  "0x" + hex.EncodeToString(key),
			Path: path,
		})
	})
}
