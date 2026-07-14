package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
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
					Name:     "hex",
					Usage:    "Seed as hex string",
					Required: true,
				},
			},
			Action: cmdLoadSeed,
		},
		{
			Name:  "load-key-bip32",
			Usage: "Load a BIP32 key pair onto the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "private-key",
					Usage:    "Private key as hex",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "chain-code",
					Usage: "Chain code as hex (optional)",
				},
				&cli.StringFlag{
					Name:  "public-key",
					Usage: "Public key as hex (optional)",
				},
			},
			Action: cmdLoadKeyBIP32,
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
	// TODO: implement generate-key
	return fmt.Errorf("generate-key: not implemented yet")
}

func cmdRemoveKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement remove-key
	return fmt.Errorf("remove-key: not implemented yet")
}

func cmdDeriveKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement derive-key
	return fmt.Errorf("derive-key: not implemented yet")
}

func cmdLoadSeed(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement load-seed
	return fmt.Errorf("load-seed: not implemented yet")
}

func cmdLoadKeyBIP32(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement load-key-bip32
	return fmt.Errorf("load-key-bip32: not implemented yet")
}

func cmdLoadLEEKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement load-lee-key
	return fmt.Errorf("load-lee-key: not implemented yet")
}

func cmdExportPublicKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement export-public-key
	return fmt.Errorf("export-public-key: not implemented yet")
}

func cmdExportPrivateKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement export-private-key
	return fmt.Errorf("export-private-key: not implemented yet")
}

func cmdExportExtendedKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement export-extended-key
	return fmt.Errorf("export-extended-key: not implemented yet")
}

func cmdExportLEEKey(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement export-lee-key
	return fmt.Errorf("export-lee-key: not implemented yet")
}

func cmdExportBIP85(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement export-bip85
	return fmt.Errorf("export-bip85: not implemented yet")
}
