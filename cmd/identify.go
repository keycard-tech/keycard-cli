package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// IdentifyCommand returns the identify command (V1 only).
func IdentifyCommand() *cli.Command {
	return &cli.Command{
		Name:  "identify",
		Usage: "Identify the card (V1 only, verifies card genuinity)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "public-key",
				Usage: "Expected public key to verify against (hex)",
			},
		},
		Action: cmdIdentify,
	}
}

func cmdIdentify(ctx context.Context, cmd *cli.Command) error {
	expectedKeyHex := cmd.String("public-key")

	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if internal.IsSecureChannelV2(kc) {
			return fmt.Errorf("identify is not supported on Secure Channel V2 cards")
		}

		pubkey, err := kc.Identify()
		if err != nil {
			return err
		}

		// Optionally verify against expected public key
		if expectedKeyHex != "" {
			expectedKey, err := internal.ParseHex(expectedKeyHex)
			if err != nil {
				return fmt.Errorf("invalid public key hex: %w", err)
			}
			if !bytes.Equal(expectedKey, pubkey) {
				return fmt.Errorf("genuinity check failed: expected 0x%x, got 0x%x", expectedKey, pubkey)
			}
		}

		if cmd.Bool("json") {
			return internal.PrintJSON(map[string]interface{}{
				"identified": true,
				"public_key": "0x" + hex.EncodeToString(pubkey),
			})
		}

		fmt.Printf("Identification OK (public key: 0x%x)\n", pubkey)
		return nil
	})
}
