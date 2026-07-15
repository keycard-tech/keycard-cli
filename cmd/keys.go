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
			Usage: "Derive a key at the given path",
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
			Name:  "load-lee-key",
			Usage: "Load a LEE key onto the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "hex",
					Usage:    "Key as hex string",
					Required: true,
				},
			},
			Action: cmdLoadLEEKey,
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
			Usage: "Export a LEE key at the given path",
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
			Usage: "Export a BIP85 derived key",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "path",
					Usage:    "Derivation path",
					Required: true,
				},
				&cli.IntFlag{
					Name:     "length",
					Usage:    "Key length in bytes",
					Required: true,
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

		if cmd.Bool("json") {
			return internal.PrintJSON(map[string]string{
				"key_uid": "0x" + hex.EncodeToString(keyUID),
			})
		}

		fmt.Printf("Key generated. UID: 0x%x\n", keyUID)
		return nil
	})
}

func cmdRemoveKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.RemoveKey(); err != nil {
			return err
		}
		fmt.Println("Key removed")
		return nil
	})
}

func cmdDeriveKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		path := cmd.String("path")
		if err := kc.DeriveKey(path); err != nil {
			return err
		}
		fmt.Printf("Key derived at path: %s\n", path)
		return nil
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
		if !validateMnemonic(mnemonic) {
			return fmt.Errorf("invalid BIP39 mnemonic")
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

		if cmd.Bool("json") {
			return internal.PrintJSON(map[string]string{
				"key_id": "0x" + hex.EncodeToString(keyID),
			})
		}

		fmt.Printf("Seed loaded. Key ID: 0x%x\n", keyID)
		return nil
	})
}

func cmdLoadLEEKey(ctx context.Context, cmd *cli.Command) error {
	key, err := internal.ParseHex(cmd.String("hex"))
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.LoadLEEKey(key); err != nil {
			return err
		}
		fmt.Println("LEE key loaded")
		return nil
	})
}

func cmdExportPublicKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		exported, err := doKeycardExportKey(kc, cmd.String("path"), cmd.Bool("current"), keycard.P2ExportKeyPublicOnly)
		if err != nil {
			return err
		}
		result := doKeycardExportKeyResult(exported, false, cmd.String("path"))
		return outputExportedKeyJSONOrPlain(cmd, result)
	})
}

func cmdExportPrivateKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		exported, err := doKeycardExportKey(kc, cmd.String("path"), cmd.Bool("current"), keycard.P2ExportKeyPrivateAndPublic)
		if err != nil {
			return err
		}
		result := doKeycardExportKeyResult(exported, true, cmd.String("path"))
		return outputExportedKeyJSONOrPlain(cmd, result)
	})
}

func cmdExportExtendedKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		exported, err := doKeycardExportKey(kc, cmd.String("path"), cmd.Bool("current"), keycard.P2ExportKeyExtendedPublic)
		if err != nil {
			return err
		}
		result := doKeycardExportExtendedKeyResult(exported, cmd.String("path"))
		return outputExportedExtendedKeyJSONOrPlain(cmd, result)
	})
}

func cmdExportLEEKey(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		path := cmd.String("path")
		key, err := kc.ExportLEEKey(path)
		if err != nil {
			return err
		}

		if cmd.Bool("json") {
			return internal.PrintJSON(map[string]string{
				"key": "0x" + hex.EncodeToString(key),
			})
		}

		fmt.Printf("LEE key: 0x%x\n", key)
		return nil
	})
}

func cmdExportBIP85(ctx context.Context, cmd *cli.Command) error {
	path := cmd.String("path")
	length := uint8(cmd.Int("length"))

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		key, err := kc.ExportBIP85(path, length)
		if err != nil {
			return err
		}

		if cmd.Bool("json") {
			return internal.PrintJSON(map[string]string{
				"key": "0x" + hex.EncodeToString(key),
			})
		}

		fmt.Printf("BIP85 key: 0x%x\n", key)
		return nil
	})
}

func outputExportedKeyJSONOrPlain(cmd interface{ Bool(string) bool }, result ExportedKeyResult) error {
	if cmd.Bool("json") {
		return internal.PrintJSON(result)
	}
	if result.PrivateKey != "" {
		fmt.Printf("Private key: %s\n", result.PrivateKey)
	}
	fmt.Printf("Public key: %s\n", result.PublicKey)
	if result.Address != "" {
		fmt.Printf("Address: %s\n", result.Address)
	}
	return nil
}

func outputExportedExtendedKeyJSONOrPlain(cmd interface{ Bool(string) bool }, result ExportedKeyResult) error {
	if cmd.Bool("json") {
		return internal.PrintJSON(result)
	}
	fmt.Printf("Public key: %s\n", result.PublicKey)
	fmt.Printf("Chain code: %s\n", result.ChainCode)
	if result.Address != "" {
		fmt.Printf("Address: %s\n", result.Address)
	}
	return nil
}
