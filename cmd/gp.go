package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
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
	// TODO: implement gp-send-apdu
	return fmt.Errorf("gp-send-apdu: not implemented yet")
}

func cmdGPSelect(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement gp-select
	return fmt.Errorf("gp-select: not implemented yet")
}

func cmdGPOpenSecureChannel(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement gp-open-secure-channel
	return fmt.Errorf("gp-open-secure-channel: not implemented yet")
}

func cmdGPDelete(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement gp-delete
	return fmt.Errorf("gp-delete: not implemented yet")
}

func cmdGPLoad(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement gp-load
	return fmt.Errorf("gp-load: not implemented yet")
}

func cmdGPInstallForInstall(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement gp-install-for-install
	return fmt.Errorf("gp-install-for-install: not implemented yet")
}

func cmdGPGetStatus(ctx context.Context, cmd *cli.Command) error {
	// TODO: implement gp-get-status
	return fmt.Errorf("gp-get-status: not implemented yet")
}
