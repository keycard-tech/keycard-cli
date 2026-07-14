package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// GPCommands returns the low-level GlobalPlatform command group.
func GPCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "gp-send-apdu",
			Usage: "Send a raw APDU command",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "hex",
					Usage:    "APDU command as hex",
					Required: true,
				},
			},
			Action: cmdGPSendAPDU,
		},
		{
			Name:  "gp-select",
			Usage: "Select an AID",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "aid",
					Usage: "AID as hex (omit for ISD)",
				},
			},
			Action: cmdGPSelect,
		},
		{
			Name:   "gp-open-secure-channel",
			Usage:  "Open a GP secure channel",
			Action: cmdGPOpenSecureChannel,
		},
		{
			Name:  "gp-delete",
			Usage: "Delete an object by AID",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "aid",
					Usage:    "AID as hex",
					Required: true,
				},
			},
			Action: cmdGPDelete,
		},
		{
			Name:  "gp-load",
			Usage: "Load a package from a CAP file",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "file",
					Usage:    "CAP file path",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "pkg-aid",
					Usage:    "Package AID as hex",
					Required: true,
				},
			},
			Action: cmdGPLoad,
		},
		{
			Name:  "gp-install-for-install",
			Usage: "Install for install",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "pkg-aid",
					Usage:    "Package AID as hex",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "applet-aid",
					Usage:    "Applet AID as hex",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "instance-aid",
					Usage:    "Instance AID as hex",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "params",
					Usage: "Installation parameters as hex",
				},
			},
			Action: cmdGPInstallForInstall,
		},
		{
			Name:   "gp-get-status",
			Usage:  "Get card status",
			Action: cmdGPGetStatus,
		},
	}
}

func cmdGPSendAPDU(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	hexData := cmd.String("hex")
	rawCmd, err := parseHex(hexData)
	if err != nil {
		return fmt.Errorf("invalid hex APDU: %w", err)
	}

	apduCmd, err := apdu.ParseCommand(rawCmd)
	if err != nil {
		return err
	}

	ch := keycardio.NewNormalChannel(card)
	resp, err := ch.Send(apduCmd)
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]interface{}{
			"sw":   fmt.Sprintf("0x%04x", resp.Sw),
			"data": "0x" + hex.EncodeToString(resp.Data),
		})
	}

	fmt.Printf("SW: 0x%04x\n", resp.Sw)
	if len(resp.Data) > 0 {
		fmt.Printf("Response: 0x%x\n", resp.Data)
	}
	return nil
}

func cmdGPSelect(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	if aidHex := cmd.String("aid"); aidHex != "" {
		aid, err := parseHex(aidHex)
		if err != nil {
			return fmt.Errorf("invalid AID hex: %w", err)
		}
		if err := gp.SelectAID(aid); err != nil {
			return err
		}
		fmt.Printf("Selected AID: %s\n", aidHex)
	} else {
		if err := gp.Select(); err != nil {
			return err
		}
		fmt.Println("Selected ISD")
	}

	return nil
}

func cmdGPOpenSecureChannel(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	if err := gp.OpenSecureChannel(); err != nil {
		return err
	}

	fmt.Println("GP secure channel opened")
	return nil
}

func cmdGPDelete(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	aidHex := cmd.String("aid")
	aid, err := parseHex(aidHex)
	if err != nil {
		return fmt.Errorf("invalid AID hex: %w", err)
	}

	if err := gp.DeleteObject(aid); err != nil {
		return err
	}

	fmt.Printf("Deleted AID: %s\n", aidHex)
	return nil
}

func cmdGPLoad(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	capFile := cmd.String("file")
	f, err := os.Open(capFile)
	if err != nil {
		return fmt.Errorf("error opening CAP file: %w", err)
	}
	defer f.Close()

	pkgAIDHex := cmd.String("pkg-aid")
	pkgAID, err := parseHex(pkgAIDHex)
	if err != nil {
		return fmt.Errorf("invalid package AID hex: %w", err)
	}

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	callback := func(index, total int) {
		log.Info("loading package", "chunk", index+1, "total", total)
	}

	if err := gp.LoadPackage(f, pkgAID, callback); err != nil {
		return err
	}

	fmt.Printf("Package loaded: %s\n", pkgAIDHex)
	return nil
}

func cmdGPInstallForInstall(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	pkgAID, err := parseHex(cmd.String("pkg-aid"))
	if err != nil {
		return fmt.Errorf("invalid package AID hex: %w", err)
	}
	appletAID, err := parseHex(cmd.String("applet-aid"))
	if err != nil {
		return fmt.Errorf("invalid applet AID hex: %w", err)
	}
	instanceAID, err := parseHex(cmd.String("instance-aid"))
	if err != nil {
		return fmt.Errorf("invalid instance AID hex: %w", err)
	}

	var params []byte
	if paramsHex := cmd.String("params"); paramsHex != "" {
		params, err = parseHex(paramsHex)
		if err != nil {
			return fmt.Errorf("invalid params hex: %w", err)
		}
	}

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	if err := gp.InstallForInstall(pkgAID, appletAID, instanceAID, params); err != nil {
		return err
	}

	fmt.Println("Install for install complete")
	return nil
}

func cmdGPGetStatus(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	status, err := gp.GetStatus()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]interface{}{
			"lifecycle": status.LifeCycle(),
		})
	}

	fmt.Printf("Card status: %s\n", status.LifeCycle())
	return nil
}
