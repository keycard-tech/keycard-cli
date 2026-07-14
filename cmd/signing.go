package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
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
	data, err := internal.ParseHex(cmd.String("hex"))
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
	hash := signHashEthereumMessage(args.First())
	return doSign(cmd, hash, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignFile(ctx context.Context, cmd *cli.Command) error {
	content, err := os.ReadFile(cmd.String("file"))
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	hash := crypto.Keccak256(content)
	return doSign(cmd, hash, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignPinless(ctx context.Context, cmd *cli.Command) error {
	data, err := internal.ParseHex(cmd.String("hex"))
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
	hash := signHashEthereumMessage(args.First())
	return doSign(cmd, hash, "", "ecdsa", true)
}

// doSign performs the signing operation. For pinless signing it uses AuthNone
// (no PIN required). For normal signing it uses AuthPIN.
func doSign(cmd *cli.Command, data []byte, path, algo string, pinless bool) error {
	if pinless {
		return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
			return doSignCore(kc, data, path, algo, pinless, cmd)
		})
	}
	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		return doSignCore(kc, data, path, algo, pinless, cmd)
	})
}

// doSignCore is the core signing logic, usable from shell.go as-is.
func doSignCore(kc *keycard.CommandSet, data []byte, path, algo string, pinless bool, cmd *cli.Command) error {
	// Check applet version for pinless
	if pinless && internal.IsAppletV4Plus(kc) {
		return fmt.Errorf("pinless signing is not available on applet version 4.0+")
	}

	var sig *types.Signature
	var err error

	if pinless {
		sig, err = kc.SignPinless(data)
	} else if path != "" {
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

	return outputSignature(cmd, sig)
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
