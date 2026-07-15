package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	keycard "github.com/status-im/keycard-go"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// DataCommands returns the data management command group.
func DataCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "get-data",
			Usage: "Get data from the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "type",
					Usage:    "Data type: public, ndef, or cash",
					Required: true,
				},
			},
			Action: cmdGetData,
		},
		{
			Name:  "store-data",
			Usage: "Store data on the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "type",
					Usage:    "Data type: public, ndef, or cash",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "hex",
					Usage: "Data as hex string",
				},
				&cli.StringFlag{
					Name:  "file",
					Usage: "Path to file containing data",
				},
			},
			Action: cmdStoreData,
		},
		{
			Name:  "get-challenge",
			Usage: "Get a random challenge from the card",
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:     "length",
					Usage:    "Challenge length in bytes",
					Required: true,
				},
			},
			Action: cmdGetChallenge,
		},
		{
			Name:  "set-ndef",
			Usage: "Set the NDEF record on the card",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hex",
					Usage: "NDEF data as hex string",
				},
				&cli.StringFlag{
					Name:  "file",
					Usage: "Path to NDEF file",
				},
			},
			Action: cmdSetNDEF,
		},
		{
			Name:   "get-status",
			Usage:  "Get card status (PIN retries, key path, etc.)",
			Action: cmdGetStatus,
		},
	}
}

func cmdGetData(ctx context.Context, cmd *cli.Command) error {
	dataType, err := parseDataType(cmd.String("type"))
	if err != nil {
		return err
	}

	return runCard(cmd, AuthSecureChannel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		data, err := doKeycardGetData(kc, dataType)
		if err != nil {
			return err
		}

		if cmd.Bool("json") {
			return internal.PrintJSON(DataResult{
				Type: cmd.String("type"),
				Data: "0x" + hex.EncodeToString(data),
			})
		}

		fmt.Printf("Data (%s): 0x%x\n", cmd.String("type"), data)
		return nil
	})
}

func cmdStoreData(ctx context.Context, cmd *cli.Command) error {
	dataType, err := parseDataType(cmd.String("type"))
	if err != nil {
		return err
	}

	var data []byte
	if hexData := cmd.String("hex"); hexData != "" {
		data, err = internal.ParseHex(hexData)
		if err != nil {
			return fmt.Errorf("invalid hex data: %w", err)
		}
	} else if filePath := cmd.String("file"); filePath != "" {
		data, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}
	} else {
		return fmt.Errorf("either --hex or --file is required")
	}

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := doKeycardStoreData(kc, dataType, data); err != nil {
			return err
		}

		fmt.Printf("Data stored (%s, %d bytes)\n", cmd.String("type"), len(data))
		return nil
	})
}

func cmdGetChallenge(ctx context.Context, cmd *cli.Command) error {
	length := uint8(cmd.Int("length"))

	return runCard(cmd, AuthSecureChannel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		challenge, err := kc.GetChallenge(length)
		if err != nil {
			return err
		}

		if cmd.Bool("json") {
			return internal.PrintJSON(ChallengeResult{
				Challenge: "0x" + hex.EncodeToString(challenge),
			})
		}

		fmt.Printf("Challenge: 0x%x\n", challenge)
		return nil
	})
}

func cmdSetNDEF(ctx context.Context, cmd *cli.Command) error {
	var ndefData []byte
	if hexData := cmd.String("hex"); hexData != "" {
		var err error
		ndefData, err = internal.ParseHex(hexData)
		if err != nil {
			return fmt.Errorf("invalid hex data: %w", err)
		}
	} else if filePath := cmd.String("file"); filePath != "" {
		var err error
		ndefData, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}
	} else {
		return fmt.Errorf("either --hex or --file is required")
	}

	return runCard(cmd, AuthPIN, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if err := kc.SetNDEF(ndefData); err != nil {
			return err
		}
		fmt.Printf("NDEF set (%d bytes)\n", len(ndefData))
		return nil
	})
}

func cmdGetStatus(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthNone, func(kc *keycard.CommandSet, _ *cli.Command) error {
		result, err := doKeycardGetStatusResult(kc)
		if err != nil {
			return err
		}

		if cmd.Bool("json") {
			return internal.PrintJSON(result)
		}

		fmt.Printf("PIN retry count: %d\n", result.PinRetryCount)
		fmt.Printf("PUK retry count: %d\n", result.PUKRetryCount)
		fmt.Printf("Key initialized: %v\n", result.KeyInitialized)
		fmt.Printf("Key path: %s\n", result.KeyPath)
		return nil
	})
}
