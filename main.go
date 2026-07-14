package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/cmd"
)

var version string = "dev"

var logger log.Logger

func initLogger(logLevel string) {
	if logLevel == "" {
		logLevel = "info"
	}

	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = log.LevelDebug
	case "info":
		level = log.LevelInfo
	case "warn":
		level = log.LevelWarn
	case "error":
		level = log.LevelError
	default:
		handler := log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelError, true)
		log.SetDefault(log.NewLogger(handler))
		logger = log.New("package", "keycard-cli")
		log.Error("invalid log level", "level", logLevel)
		return
	}

	handler := log.NewTerminalHandlerWithLevel(os.Stderr, level, true)
	log.SetDefault(log.NewLogger(handler))
	logger = log.New("package", "keycard-cli")
}

func main() {
	app := &cli.Command{
		Name:    "keycard",
		Usage:   "Keycard CLI tool — manage Status Keycard hardware wallets",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Value:   "info",
				Usage:   `Log level, one of: "error", "warn", "info", "debug"`,
			},
			&cli.StringFlag{
				Name:  "pin",
				Usage: "PIN (or KEYCARD_PIN env var)",
			},
			&cli.StringFlag{
				Name:  "puk",
				Usage: "PUK (or KEYCARD_PUK env var)",
			},
			&cli.StringFlag{
				Name:  "pairing-password",
				Usage: "Pairing password (or KEYCARD_PAIRING_PASSWORD env var)",
			},
			&cli.StringFlag{
				Name:  "secrets-file",
				Usage: "Path to file with pin/puk/pairing-password (one per line)",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Output in JSON format",
			},
			&cli.BoolFlag{
				Name:    "yes",
				Aliases: []string{"y"},
				Usage:   "Skip interactive confirmations",
			},
			&cli.StringFlag{
				Name:  "reader",
				Usage: "Specific reader name (or auto-detect)",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			initLogger(cmd.String("log-level"))
			return ctx, nil
		},
		Commands: []*cli.Command{
			// Lifecycle commands
			{
				Name:     "lifecycle",
				Usage:    "Lifecycle commands (install, init, delete, etc.)",
				Commands: cmd.LifecycleCommands(),
			},

			// Pairing commands
			{
				Name:     "pairing",
				Usage:    "Secure channel / pairing commands",
				Commands: cmd.PairingCommands(),
			},

			// Key management commands
			{
				Name:     "keys",
				Usage:    "Key management commands (generate, export, derive, etc.)",
				Commands: cmd.KeyCommands(),
			},

			// Signing commands
			{
				Name:     "sign",
				Usage:    "Signing commands",
				Commands: cmd.SigningCommands(),
			},

			// Credentials commands
			{
				Name:     "credentials",
				Usage:    "Credential management commands (PIN, PUK, pairing password)",
				Commands: cmd.CredentialsCommands(),
			},

			// Data commands
			{
				Name:     "data",
				Usage:    "Data management commands (get-data, store-data, NDEF)",
				Commands: cmd.DataCommands(),
			},

			// Pinless commands
			{
				Name:     "pinless",
				Usage:    "Pinless signing commands (applet < 4.0 only)",
				Commands: cmd.PinlessCommands(),
			},

			// Metadata commands
			{
				Name:     "metadata",
				Usage:    "Metadata commands (card name)",
				Commands: cmd.MetadataCommands(),
			},

			// Identify command
			cmd.IdentifyCommand(),

			// Cash command
			cmd.CashCommand(),

			// GP (GlobalPlatform) low-level commands
			{
				Name:     "gp",
				Usage:    "Low-level GlobalPlatform commands",
				Commands: cmd.GPCommands(),
			},

			// Shell (scripting mode)
			cmd.ShellCommand(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
