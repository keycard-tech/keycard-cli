package cmd

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// loadIdentTestCAKey is the CA private key used for test certificate generation.
const loadIdentTestCAKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

// IdentCommands returns the identity management commands.
func IdentCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "load-ident",
			Usage: "Load an identity certificate onto the Ident applet",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hex",
					Usage: "Certificate data as hex string (loaded as-is)",
				},
				&cli.BoolFlag{
					Name:  "test",
					Usage: "Generate a random test certificate and load it",
				},
			},
			Action: cmdLoadIdent,
		},
	}
}

func cmdLoadIdent(ctx context.Context, cmd *cli.Command) error {
	hexData := cmd.String("hex")
	testMode := cmd.Bool("test")

	if hexData == "" && !testMode {
		return fmt.Errorf("either --hex or --test is required")
	}
	if hexData != "" && testMode {
		return fmt.Errorf("only one of --hex or --test can be specified")
	}

	var data []byte
	var err error

	if testMode {
		data, err = doGenerateTestCertificate()
		if err != nil {
			return fmt.Errorf("failed to generate test certificate: %w", err)
		}
	} else {
		data, err = internal.ParseHex(hexData)
		if err != nil {
			return fmt.Errorf("invalid hex data: %w", err)
		}
	}

	return runIdent(cmd, func(identKC *keycard.IdentCommandSet, _ *cli.Command) error {
		if err := identKC.Select(); err != nil {
			return err
		}
		if _, err := identKC.StoreData(data); err != nil {
			return err
		}
		return PrintResultCLI(cmd, LoadIdentResult{
			Bytes: len(data),
		})
	})
}

// doGenerateTestCertificate generates a random identity certificate signed by the test CA.
func doGenerateTestCertificate() ([]byte, error) {
	caPrivBytes, err := hex.DecodeString(loadIdentTestCAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA private key: %w", err)
	}
	caPriv := secp256k1.PrivKeyFromBytes(caPrivBytes)

	cert, err := types.GenerateNewCertificate(caPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return cert.ToStoreData()
}
