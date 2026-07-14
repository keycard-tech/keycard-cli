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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
		return err
	}

	if err := internal.AutoAuth(kc, secrets); err != nil {
		return err
	}
	defer internal.AutoUnpair(kc)

	var seed []byte

	mnemonic := cmd.String("mnemonic")
	seedHex := cmd.String("hex")

	if mnemonic != "" && seedHex != "" {
		return fmt.Errorf("cannot specify both --mnemonic and --hex")
	}
	if mnemonic == "" && seedHex == "" {
		return fmt.Errorf("must specify either --mnemonic or --hex")
	}

	if mnemonic != "" {
		if !validateMnemonic(mnemonic) {
			return fmt.Errorf("invalid BIP39 mnemonic")
		}
		seed = types.BinarySeedFromPhrase(mnemonic, "")
	} else {
		seed, err = parseHex(seedHex)
		if err != nil {
			return fmt.Errorf("invalid hex seed: %w", err)
		}
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)
	if err := internal.RequirePIN(secrets); err != nil {
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

// validateMnemonic checks that the mnemonic has a valid word count
// and that each word exists in the BIP39 English wordlist.
func validateMnemonic(phrase string) bool {
	words := strings.Fields(phrase)
	// Valid mnemonic lengths: 12, 15, 18, 21, 24 words
	n := len(words)
	if n%3 != 0 || n < 12 || n > 24 {
		return false
	}
	for _, word := range words {
		if !containsWord(word) {
			return false
		}
	}
	return true
}

// containsWord checks if a word exists in the BIP39 English wordlist.
func containsWord(word string) bool {
	for i := 0; i < len(types.BIP39EnglishWordlist); i++ {
		if types.BIP39EnglishWordlist[i] == word {
			return true
		}
	}
	return false
}
