package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	keycard "github.com/status-im/keycard-go"
	keycardio "github.com/status-im/keycard-go/io"
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

	dataType := parseDataType(cmd.String("type"))
	if dataType < 0 {
		return fmt.Errorf("invalid data type: %s (must be public, ndef, or cash)", cmd.String("type"))
	}

	data, err := kc.GetData(uint8(dataType))
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"type": cmd.String("type"),
			"data": "0x" + hex.EncodeToString(data),
		})
	}

	fmt.Printf("Data (%s): 0x%x\n", cmd.String("type"), data)
	return nil
}

func cmdStoreData(ctx context.Context, cmd *cli.Command) error {
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

	dataType := parseDataType(cmd.String("type"))
	if dataType < 0 {
		return fmt.Errorf("invalid data type: %s (must be public, ndef, or cash)", cmd.String("type"))
	}

	var data []byte
	if hexData := cmd.String("hex"); hexData != "" {
		var err error
		data, err = parseHex(hexData)
		if err != nil {
			return fmt.Errorf("invalid hex data: %w", err)
		}
	} else if filePath := cmd.String("file"); filePath != "" {
		var err error
		data, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}
	} else {
		return fmt.Errorf("either --hex or --file is required")
	}

	// Auto-chunk if data > 240 bytes
	if len(data) > 240 {
		return storeDataChunked(kc, uint8(dataType), data)
	}

	if err := kc.StoreData(uint8(dataType), data); err != nil {
		return err
	}

	fmt.Printf("Data stored (%s, %d bytes)\n", cmd.String("type"), len(data))
	return nil
}

func storeDataChunked(kc *keycard.CommandSet, dataType uint8, data []byte) error {
	chunkSize := 220
	offset := uint16(0)

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		if offset > 0 {
			if err := kc.StoreDataWithOffset(dataType, chunk, offset); err != nil {
				return err
			}
		} else {
			if err := kc.StoreData(dataType, chunk); err != nil {
				return err
			}
		}
		offset += uint16(len(chunk))
	}

	return nil
}

func cmdGetChallenge(ctx context.Context, cmd *cli.Command) error {
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

	length := uint8(cmd.Int("length"))
	challenge, err := kc.GetChallenge(length)
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"challenge": "0x" + hex.EncodeToString(challenge),
		})
	}

	fmt.Printf("Challenge: 0x%x\n", challenge)
	return nil
}

func cmdSetNDEF(ctx context.Context, cmd *cli.Command) error {
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

	var ndefData []byte
	if hexData := cmd.String("hex"); hexData != "" {
		var err error
		ndefData, err = parseHex(hexData)
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

	if err := kc.SetNDEF(ndefData); err != nil {
		return err
	}

	fmt.Printf("NDEF set (%d bytes)\n", len(ndefData))
	return nil
}

func cmdGetStatus(ctx context.Context, cmd *cli.Command) error {
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

	appStatus, err := kc.GetStatusApplication()
	if err != nil {
		return err
	}

	keyStatus, err := kc.GetStatusKeyPath()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]interface{}{
			"pin_retry_count": appStatus.PinRetryCount,
			"puk_retry_count": appStatus.PUKRetryCount,
			"key_initialized": appStatus.KeyInitialized,
			"key_path":        keyStatus.Path,
		})
	}

	fmt.Printf("PIN retry count: %d\n", appStatus.PinRetryCount)
	fmt.Printf("PUK retry count: %d\n", appStatus.PUKRetryCount)
	fmt.Printf("Key initialized: %v\n", appStatus.KeyInitialized)
	fmt.Printf("Key path: %s\n", keyStatus.Path)
	return nil
}

func parseDataType(s string) int {
	switch strings.ToLower(s) {
	case "public":
		return int(keycard.P1StoreDataPublic)
	case "ndef":
		return int(keycard.P1StoreDataNDEF)
	case "cash":
		return int(keycard.P1StoreDataCash)
	default:
		return -1
	}
}
