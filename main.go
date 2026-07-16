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
			&cli.StringFlag{
				Name:  "card-ca",
				Usage: "CA public key for V2 certificate verification (hex, 33 bytes compressed)",
			},
			&cli.BoolFlag{
				Name:  "test-card",
				Usage: "Use test card CA (shortcut for --card-ca with test CA public key)",
			},
			&cli.StringFlag{
				Name:  "whitelist-card",
				Usage: "Whitelisted card identity public key (hex, 33 bytes compressed)",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			initLogger(cmd.String("log-level"))
			return ctx, nil
		},
		Commands: func() []*cli.Command {
			cmds := cmd.LifecycleCommands()
			cmds = append(cmds, cmd.PairingCommands()...)
			cmds = append(cmds, cmd.KeyCommands()...)
			cmds = append(cmds, cmd.SigningCommands()...)
			cmds = append(cmds, cmd.CredentialsCommands()...)
			cmds = append(cmds, cmd.DataCommands()...)
			cmds = append(cmds, cmd.PinlessCommands()...)
			cmds = append(cmds, cmd.MetadataCommands()...)
			cmds = append(cmds, cmd.IdentifyCommand())
			cmds = append(cmds, cmd.CashCommand())
			cmds = append(cmds, cmd.IdentCommands()...)
			cmds = append(cmds, cmd.ShellCommand())
			return cmds
		}(),
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
