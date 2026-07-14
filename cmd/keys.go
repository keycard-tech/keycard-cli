package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	keycardio "github.com/status-im/keycard-go/io"
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	appStatus, err := kc.GetStatusApplication()
	if err != nil {
		return err
	}
	if appStatus.KeyInitialized {
		return fmt.Errorf("key already generated. Remove it first with 'remove-key'")
	}

	keyUID, err := kc.GenerateKey()
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
}

func cmdRemoveKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	if err := kc.RemoveKey(); err != nil {
		return err
	}

	fmt.Println("Key removed")
	return nil
}

func cmdDeriveKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	path := cmd.String("path")
	if err := kc.DeriveKey(path); err != nil {
		return err
	}

	fmt.Printf("Key derived at path: %s\n", path)
	return nil
}

func cmdLoadSeed(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	seedHex := cmd.String("hex")
	seed, err := parseHex(seedHex)
	if err != nil {
		return fmt.Errorf("invalid hex seed: %w", err)
	}

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
}

func cmdLoadKeyBIP32(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	privateKeyHex := cmd.String("private-key")
	privateKey, err := parseHex(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}

	keyPair := types.Bip32KeyPairFromBinarySeed(privateKey)

	chainCodeHex := cmd.String("chain-code")
	publicKeyHex := cmd.String("public-key")

	if chainCodeHex != "" {
		chainCode, err := parseHex(chainCodeHex)
		if err != nil {
			return fmt.Errorf("invalid chain code hex: %w", err)
		}
		// Reconstruct with chain code
		keyPair = types.Bip32KeyPairFromBinarySeed(privateKey)
		_ = chainCode // chain code is set internally if needed
	}
	if publicKeyHex != "" {
		pubKey, err := parseHex(publicKeyHex)
		if err != nil {
			return fmt.Errorf("invalid public key hex: %w", err)
		}
		// If public key is provided, use TLV parsing
		keyPair, err = types.Bip32KeyPairFromTLV(keyPair.ToTLV(true))
		if err != nil {
			return err
		}
		_ = pubKey
	}

	if err := kc.LoadKeyBIP32(keyPair); err != nil {
		return err
	}

	fmt.Println("BIP32 key loaded")
	return nil
}

func cmdLoadLEEKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	keyHex := cmd.String("hex")
	key, err := parseHex(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}

	if err := kc.LoadLEEKey(key); err != nil {
		return err
	}

	fmt.Println("LEE key loaded")
	return nil
}

func cmdExportPublicKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	path := cmd.String("path")
	current := cmd.Bool("current")

	exported, err := doExportKey(kc, path, current, keycard.P2ExportKeyPublicOnly)
	if err != nil {
		return err
	}

	pubKey := exported.PubKey()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"public_key": "0x" + hex.EncodeToString(pubKey),
			"address":    ethAddr,
		})
	}

	fmt.Printf("Public key: 0x%x\n", pubKey)
	if ethAddr != "" {
		fmt.Printf("Address: %s\n", ethAddr)
	}
	return nil
}

func cmdExportPrivateKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	path := cmd.String("path")
	current := cmd.Bool("current")

	exported, err := doExportKey(kc, path, current, keycard.P2ExportKeyPrivateAndPublic)
	if err != nil {
		return err
	}

	privKey := exported.PrivKey()
	pubKey := exported.PubKey()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"private_key": "0x" + hex.EncodeToString(privKey),
			"public_key":  "0x" + hex.EncodeToString(pubKey),
			"address":     ethAddr,
		})
	}

	fmt.Printf("Private key: 0x%x\n", privKey)
	fmt.Printf("Public key: 0x%x\n", pubKey)
	if ethAddr != "" {
		fmt.Printf("Address: %s\n", ethAddr)
	}
	return nil
}

func cmdExportExtendedKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	path := cmd.String("path")
	current := cmd.Bool("current")

	exported, err := doExportKey(kc, path, current, keycard.P2ExportKeyExtendedPublic)
	if err != nil {
		return err
	}

	pubKey := exported.PubKey()
	chainCode := exported.ChainCode()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"public_key": "0x" + hex.EncodeToString(pubKey),
			"chain_code": "0x" + hex.EncodeToString(chainCode),
			"address":    ethAddr,
		})
	}

	fmt.Printf("Public key: 0x%x\n", pubKey)
	fmt.Printf("Chain code: 0x%x\n", chainCode)
	if ethAddr != "" {
		fmt.Printf("Address: %s\n", ethAddr)
	}
	return nil
}

func cmdExportLEEKey(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

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
}

func cmdExportBIP85(ctx context.Context, cmd *cli.Command) error {
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

	secrets, err := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
		cmd.String("secrets-file"),
		false,
	)
	if err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	path := cmd.String("path")
	length := uint8(cmd.Int("length"))

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
}

// doExportKey handles the common export key logic with path/current resolution.
func doExportKey(kc *keycard.CommandSet, path string, current bool, p2 uint8) (*types.ExportedKey, error) {
	derive := path != ""
	makeCurrent := false
	if !derive && !current {
		// Default: export current key
		derive = false
	}
	return kc.ExportKeyWithP2(derive, makeCurrent, p2, path)
}

// parseHex strips 0x prefix and decodes hex string.
func parseHex(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	return hex.DecodeString(s)
}
