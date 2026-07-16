package cmd

import (
	"context"
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
	return doSignCLI(cmd, data, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignMessage(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() == 0 {
		return fmt.Errorf("message argument required")
	}
	hash := hashEthereumMessage(args.First())
	return doSignCLI(cmd, hash, cmd.String("path"), cmd.String("algo"), false)
}

func cmdSignFile(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	hash := crypto.Keccak256(content)
	return doSignCLIWithFile(cmd, hash, cmd.String("path"), cmd.String("algo"), false, filePath)
}

func cmdSignPinless(ctx context.Context, cmd *cli.Command) error {
	data, err := internal.ParseHex(cmd.String("hex"))
	if err != nil {
		return fmt.Errorf("invalid hex data: %w", err)
	}
	return doSignCLI(cmd, data, "", "ecdsa", true)
}

func cmdSignMessagePinless(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() == 0 {
		return fmt.Errorf("message argument required")
	}
	hash := hashEthereumMessage(args.First())
	return doSignCLI(cmd, hash, "", "ecdsa", true)
}

func doSignCLI(cmd *cli.Command, data []byte, path, algo string, pinless bool) error {
	authLevel := AuthPIN
	if pinless {
		authLevel = AuthNone
	}
	return runCard(cmd, authLevel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) && path == "" {
			return fmt.Errorf("--path is required for applet version 4.0+")
		}
		sig, err := signWithParams(kc, data, path, algo, pinless)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, newSignatureResult(sig))
	})
}

func doSignCLIWithFile(cmd *cli.Command, data []byte, path, algo string, pinless bool, file string) error {
	authLevel := AuthPIN
	if pinless {
		authLevel = AuthNone
	}
	return runCard(cmd, authLevel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsAppletV4Plus(kc) && path == "" {
			return fmt.Errorf("--path is required for applet version 4.0+")
		}
		sig, err := signWithParams(kc, data, path, algo, pinless)
		if err != nil {
			return err
		}
		result := newSignatureResult(sig)
		result.File = file
		return PrintResultCLI(cmd, result)
	})
}

// signWithParams performs signing with the given parameters using core functions.
func signWithParams(kc *keycard.CommandSet, data []byte, path, algo string, pinless bool) (*types.Signature, error) {
	if pinless {
		return doKeycardSignPinless(kc, data)
	}
	if path != "" {
		switch strings.ToLower(algo) {
		case "schnorr":
			return doKeycardSignWithPathAndAlgo(kc, data, path, keycard.P2SignBIP340Schnorr)
		default:
			return doKeycardSignWithPath(kc, data, path)
		}
	}
	return doKeycardSign(kc, data)
}
