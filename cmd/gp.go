package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
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
	rawCmd, err := internal.ParseHex(cmd.String("hex"))
	if err != nil {
		return fmt.Errorf("invalid hex APDU: %w", err)
	}

	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		resp, err := doGPSendAPDU(gp, rawCmd)
		if err != nil {
			return err
		}
		if resp.Sw != apdu.SwOK {
			return apdu.NewErrBadResponse(resp.Sw, "unexpected response")
		}
		return PrintResultCLI(cmd, GPResult{
			SW:      resp.Sw,
			Data:    resp.Data,
			SWStr:   fmt.Sprintf("0x%04x", resp.Sw),
			DataHex: "0x" + hex.EncodeToString(resp.Data),
		})
	})
}

func cmdGPSelect(ctx context.Context, cmd *cli.Command) error {
	var aid []byte
	if aidHex := cmd.String("aid"); aidHex != "" {
		var err error
		aid, err = internal.ParseHex(aidHex)
		if err != nil {
			return fmt.Errorf("invalid AID hex: %w", err)
		}
	}

	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		if err := doGPSelect(gp, aid); err != nil {
			return err
		}
		if aid != nil {
			return PrintResultCLI(cmd, ActionResult{Message: "Selected AID: " + cmd.String("aid")})
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Selected ISD"})
	})
}

func cmdGPOpenSecureChannel(ctx context.Context, cmd *cli.Command) error {
	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		return PrintResultCLI(cmd, ActionResult{Message: "GP secure channel opened"})
	})
}

func cmdGPDelete(ctx context.Context, cmd *cli.Command) error {
	aid, err := internal.ParseHex(cmd.String("aid"))
	if err != nil {
		return fmt.Errorf("invalid AID hex: %w", err)
	}

	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		if err := gp.DeleteObject(aid); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Deleted AID: " + cmd.String("aid")})
	})
}

func cmdGPLoad(ctx context.Context, cmd *cli.Command) error {
	capFile := cmd.String("file")
	f, err := os.Open(capFile)
	if err != nil {
		return fmt.Errorf("error opening CAP file: %w", err)
	}
	defer f.Close()

	pkgAID, err := internal.ParseHex(cmd.String("pkg-aid"))
	if err != nil {
		return fmt.Errorf("invalid package AID hex: %w", err)
	}

	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		callback := func(index, total int) {
			log.Info("loading package", "chunk", index+1, "total", total)
		}
		if err := gp.LoadPackage(f, pkgAID, callback); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Package loaded: " + cmd.String("pkg-aid")})
	})
}

func cmdGPInstallForInstall(ctx context.Context, cmd *cli.Command) error {
	pkgAID, err := internal.ParseHex(cmd.String("pkg-aid"))
	if err != nil {
		return fmt.Errorf("invalid package AID hex: %w", err)
	}
	appletAID, err := internal.ParseHex(cmd.String("applet-aid"))
	if err != nil {
		return fmt.Errorf("invalid applet AID hex: %w", err)
	}
	instanceAID, err := internal.ParseHex(cmd.String("instance-aid"))
	if err != nil {
		return fmt.Errorf("invalid instance AID hex: %w", err)
	}

	var params []byte
	if paramsHex := cmd.String("params"); paramsHex != "" {
		params, err = internal.ParseHex(paramsHex)
		if err != nil {
			return fmt.Errorf("invalid params hex: %w", err)
		}
	}

	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		if err := gp.InstallForInstall(pkgAID, appletAID, instanceAID, params); err != nil {
			return err
		}
		return PrintResultCLI(cmd, ActionResult{Message: "Install for install complete"})
	})
}

func cmdGPGetStatus(ctx context.Context, cmd *cli.Command) error {
	return runGP(cmd, func(gp *globalplatform.CommandSet, _ *cli.Command) error {
		status, err := doGPGetStatus(gp)
		if err != nil {
			return err
		}
		return PrintResultCLI(cmd, GPStatusResult{Lifecycle: status.LifeCycle()})
	})
}
