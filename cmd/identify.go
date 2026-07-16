package cmd

import (
	"context"
	"encoding/hex"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// IdentifyCommand returns the identify command (applet < 4.0 only).
func IdentifyCommand() *cli.Command {
	return &cli.Command{
		Name:  "identify",
		Usage: "Identify the card (applet < 4.0 only)",
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
			return fmt.Errorf("identify is not supported on Secure Channel V2")
		}

		var expectedKey []byte
		if expectedKeyHex != "" {
			var err error
			expectedKey, err = internal.ParseHex(expectedKeyHex)
			if err != nil {
				return fmt.Errorf("invalid public key hex: %w", err)
			}
		}

		pubkey, err := doKeycardIdentify(kc, expectedKey)
		if err != nil {
			return err
		}

		return PrintResultCLI(cmd, IdentifyResult{
			Identified: true,
			PublicKey:  "0x" + hex.EncodeToString(pubkey),
		})
	})
}
