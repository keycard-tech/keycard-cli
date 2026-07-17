package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	keycard "github.com/keycard-tech/keycard-go/v4"
	"github.com/urfave/cli/v3"

	"github.com/keycard-tech/keycard-cli/internal"
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
			Usage: "Get a random challenge from the card (applet >= 4.0 only)",
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
		return PrintResultCLI(cmd, DataResult{
			Type: cmd.String("type"),
			Data: "0x" + hex.EncodeToString(data),
		})
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
		return PrintResultCLI(cmd, StoreDataResult{
			Type:  cmd.String("type"),
			Bytes: len(data),
		})
	})
}

func cmdGetChallenge(ctx context.Context, cmd *cli.Command) error {
	length := uint8(cmd.Int("length"))

	return runCard(cmd, AuthSecureChannel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		if !internal.IsAppletV4Plus(kc) {
			return fmt.Errorf("get-challenge is only available on applet version 4.0+")
		}
		challenge, err := kc.GetChallenge(length)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, ChallengeResult{
			Challenge: "0x" + hex.EncodeToString(challenge),
		})
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
		return PrintResultCLI(cmd, SetNDEFResult{Bytes: len(ndefData)})
	})
}

func cmdGetStatus(ctx context.Context, cmd *cli.Command) error {
	return runCard(cmd, AuthSecureChannel, func(kc *keycard.CommandSet, _ *cli.Command) error {
		result, err := doKeycardGetStatusResult(kc)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, result)
	})
}
