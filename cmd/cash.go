package cmd

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// CashCommand returns the cash applet command group.
func CashCommand() *cli.Command {
	return &cli.Command{
		Name:  "cash-sign",
		Usage: "Sign with the Cash applet",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "hex",
				Usage:    "Data to sign as hex (32 bytes)",
				Required: true,
			},
		},
		Action: cmdCashSign,
	}
}

func cmdCashSign(ctx context.Context, cmd *cli.Command) error {
	hexData := cmd.String("hex")
	data, err := internal.ParseHex(hexData)
	if err != nil {
		return fmt.Errorf("invalid hex data: %w", err)
	}

	return runCash(cmd, func(cashKC *keycard.CashCommandSet, _ *cli.Command) error {
		sig, err := cashKC.Sign(data)
		if err != nil {
			return err
		}
		return outputSignature(cmd, sig)
	})
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
