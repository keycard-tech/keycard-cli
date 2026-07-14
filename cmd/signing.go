package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
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
					Name:   "algo",
					Usage:  "Signature algorithm: ecdsa (default) or schnorr",
					Value:  "ecdsa",
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
					Name:   "algo",
					Usage:  "Signature algorithm: ecdsa (default) or schnorr",
					Value:  "ecdsa",
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
					Name:   "algo",
					Usage:  "Signature algorithm: ecdsa (default) or schnorr",
					Value:  "ecdsa",
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
			Name:  "sign-message-pinless",
			Usage: "Sign a message without PIN (applet < 4.0 only)",
			Action: cmdSignMessagePinless,
		},
	}
}

func cmdSign(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement sign
	return fmt.Errorf("sign: not implemented yet")
}

func cmdSignMessage(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement sign-message
	return fmt.Errorf("sign-message: not implemented yet")
}

func cmdSignFile(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement sign-file
	return fmt.Errorf("sign-file: not implemented yet")
}

func cmdSignPinless(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement sign-pinless
	return fmt.Errorf("sign-pinless: not implemented yet")
}

func cmdSignMessagePinless(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement sign-message-pinless
	return fmt.Errorf("sign-message-pinless: not implemented yet")
}
