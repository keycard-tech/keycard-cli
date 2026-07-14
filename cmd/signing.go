package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// SigningCommands returns the signing command group.
func SigningCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "sign",
			Usage: "Sign a 32-byte hash",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "hex",
					Usage:    "Data to sign as hex (32 bytes)",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "Derivation path (optional)",
				},
				&cli.StringFlag{
					Name:  "algo",
					Usage: "Signature algorithm: ecdsa (default) or schnorr",
					Value: "ecdsa",
				},
			},
			Action: cmdSign,
		},
		{
			Name:  "sign-message",
			Usage: "Sign a message (Ethereum Signed Message format)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "path",
					Usage: "Derivation path (optional)",
				},
				&cli.StringFlag{
					Name:  "algo",
					Usage: "Signature algorithm: ecdsa (default) or schnorr",
					Value: "ecdsa",
				},
			},
			Action: cmdSignMessage,
		},
		{
			Name:  "sign-file",
			Usage: "Sign a file (hashes file content)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "file",
					Usage:    "Path to file to sign",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "Derivation path (optional)",
				},
				&cli.StringFlag{
					Name:  "algo",
					Usage: "Signature algorithm: ecdsa (default) or schnorr",
					Value: "ecdsa",
				},
			},
			Action: cmdSignFile,
		},
		{
			Name:  "sign-pinless",
			Usage: "Sign without PIN verification (applet < 4.0 only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "hex",
					Usage:    "Data to sign as hex (32 bytes)",
					Required: true,
				},
			},
			Action: cmdSignPinless,
		},
		{
			Name:   "sign-message-pinless",
			Usage:  "Sign a message without PIN (applet < 4.0 only)",
			Action: cmdSignMessagePinless,
		},
	}
}

func cmdSign(ctx context.Context, cmd *cli.Command) error {
	hexData := cmd.String("hex")
	data, err := parseHex(hexData)
	if err != nil {
		return fmt.Errorf("invalid hex data: %w", err)
	}

	return doSign(cmd, data, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignMessage(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() == 0 {
		return fmt.Errorf("message argument required")
	}
	message := args.First()
	hash := signHashEthereumMessage(message)

	return doSign(cmd, hash, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignFile(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	hash := crypto.Keccak256(content)

	return doSign(cmd, hash, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignPinless(ctx context.Context, cmd *cli.Command) error {
	hexData := cmd.String("hex")
	data, err := parseHex(hexData)
	if err != nil {
		return fmt.Errorf("invalid hex data: %w", err)
	}

	return doSign(cmd, data, "", "ecdsa", true)
}

func cmdSignMessagePinless(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() == 0 {
		return fmt.Errorf("message argument required")
	}
	message := args.First()
	hash := signHashEthereumMessage(message)

	return doSign(cmd, hash, "", "ecdsa", true)
}

func doSign(cmd *cli.Command, data []byte, path, algo string, pinless bool) error {
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

	// Check applet version for pinless
	if pinless && internal.IsAppletV4Plus(kc) {
		return fmt.Errorf("pinless signing is not available on applet version 4.0+")
	}

	var sig *types.Signature

	if pinless {
		sig, err = kc.SignPinless(data)
		if err != nil {
			return err
		}
	} else {
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

		if path != "" {
			switch strings.ToLower(algo) {
			case "schnorr":
				sig, err = kc.SignWithPathAndAlgo(data, path, keycard.P2SignBIP340Schnorr)
			default: // ecdsa
				sig, err = kc.SignWithPath(data, path)
			}
		} else {
			sig, err = kc.Sign(data)
		}
		if err != nil {
			return err
		}
	}

	return outputSignature(cmd, sig)
}

func outputSignature(cmd *cli.Command, sig *types.Signature) error {
	ethSig := append(sig.R(), sig.S()...)
	ethSig = append(ethSig, sig.V()+27)
	pubKey := sig.PubKey()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]interface{}{
			"signature": map[string]interface{}{
				"r":             "0x" + hex.EncodeToString(sig.R()),
				"s":             "0x" + hex.EncodeToString(sig.S()),
				"v":             int(sig.V()),
				"eth_signature": "0x" + hex.EncodeToString(ethSig),
				"public_key":    "0x" + hex.EncodeToString(pubKey),
				"address":       ethAddr,
			},
		})
	}

	fmt.Printf("Signature R: 0x%x\n", sig.R())
	fmt.Printf("Signature S: 0x%x\n", sig.S())
	fmt.Printf("Signature V: %d\n", sig.V())
	fmt.Printf("ETH Signature: 0x%x\n", ethSig)
	fmt.Printf("Public key: 0x%x\n", pubKey)
	if ethAddr != "" {
		fmt.Printf("Address: %s\n", ethAddr)
	}
	return nil
}

func signHashEthereumMessage(message string) []byte {
	data := []byte(message)
	if strings.HasPrefix(message, "0x") {
		if value, err := hex.DecodeString(message[2:]); err == nil {
			data = value
		}
	}
	wrappedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(wrappedMessage))
}
