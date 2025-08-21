package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	stdlog "log"
	"os"
	"strconv"
	"strings"

	"github.com/ebfe/scard"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v3"
)

var version string

type commandFunc func(*scard.Card) error

var (
	logger = log.New("package", "keycard-cli")
)

func initLogger(logLevel string) {
	if logLevel == "" {
		logLevel = "info"
	}

	level, err := log.LvlFromString(strings.ToLower(logLevel))
	if err != nil {
		stdlog.Fatal(err)
	}

	handler := log.StreamHandler(os.Stderr, log.TerminalFormat(true))
	filteredHandler := log.LvlFilterHandler(level, handler)
	log.Root().SetHandler(filteredHandler)
}

func main() {
	app := &cli.Command{
		Name:    "keycard",
		Usage:   "Keycard CLI tool",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Value:   "info",
				Usage:   `Log level, one of: "error", "warn", "info", "debug", and "trace"`,
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			initLogger(cmd.String("log-level"))
			return ctx, nil
		},
		Commands: []*cli.Command{
			{
				Name:   "version",
				Usage:  "Show version information",
				Action: cliCommandVersion,
			},
			{
				Name:  "install",
				Usage: "Install applets to the card",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "applet-file",
						Aliases:  []string{"a"},
						Usage:    "applet cap file path",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "keycard-applet",
						Usage: "install keycard applet",
						Value: true,
					},
					&cli.BoolFlag{
						Name:  "cash-applet",
						Usage: "install cash applet",
						Value: true,
					},
					&cli.BoolFlag{
						Name:  "ndef-applet",
						Usage: "install NDEF applet",
						Value: true,
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "force applet installation if already installed",
					},
					&cli.StringFlag{
						Name:  "ndef",
						Usage: "Specify a URL to use in the NDEF record. Use the {{.cashAddress}} variable to get the cash address: http://example.com/{{.cashAddress}}.",
					},
				},
				Action: cliCommandInstall,
			},
			{
				Name:   "info",
				Usage:  "Show card information",
				Action: cliCommandInfo,
			},
			{
				Name:   "delete",
				Usage:  "Delete applets from the card",
				Action: cliCommandDelete,
			},
			{
				Name:   "init",
				Usage:  "Initialize the card",
				Action: cliCommandInit,
			},
			{
				Name:   "shell",
				Usage:  "Start interactive shell",
				Action: cliCommandShell,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		stdlog.Fatal(err)
	}
}

func fail(msg string, ctx ...interface{}) {
	logger.Error(msg, ctx...)
	os.Exit(1)
}

func waitForCard(ctx *scard.Context, readers []string) (int, error) {
	rs := make([]scard.ReaderState, len(readers))

	for i := range rs {
		rs[i].Reader = readers[i]
		rs[i].CurrentState = scard.StateUnaware
	}

	for {
		for i := range rs {
			if rs[i].EventState&scard.StatePresent != 0 {
				return i, nil
			}

			rs[i].CurrentState = rs[i].EventState
		}

		err := ctx.GetStatusChange(rs, -1)
		if err != nil {
			return -1, err
		}
	}
}

func connectToCard() (*scard.Card, func(), error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, nil, fmt.Errorf("error establishing card context: %w", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return nil, nil, fmt.Errorf("error getting readers: %w", err)
	}

	logger.Info("waiting for a card")
	if len(readers) == 0 {
		ctx.Release()
		return nil, nil, errors.New("no smartcard reader found")
	}

	index, err := waitForCard(ctx, readers)
	if err != nil {
		ctx.Release()
		return nil, nil, fmt.Errorf("error waiting for card: %w", err)
	}

	logger.Info("card found", "index", index)
	reader := readers[index]

	logger.Debug("using reader", "name", reader)
	logger.Debug("connecting to card", "reader", reader)
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, nil, fmt.Errorf("error connecting to card: %w", err)
	}

	status, err := card.Status()
	if err != nil {
		card.Disconnect(scard.ResetCard)
		ctx.Release()
		return nil, nil, fmt.Errorf("error getting card status: %w", err)
	}

	switch status.ActiveProtocol {
	case scard.ProtocolT0:
		logger.Debug("card protocol", "T", "0")
	case scard.ProtocolT1:
		logger.Debug("card protocol", "T", "1")
	default:
		logger.Debug("card protocol", "T", "unknown")
	}

	cleanup := func() {
		if err := card.Disconnect(scard.ResetCard); err != nil {
			logger.Error("error disconnecting card", "error", err)
		}
		if err := ctx.Release(); err != nil {
			logger.Error("error releasing context", "error", err)
		}
	}

	return card, cleanup, nil
}

func cliCommandVersion(ctx context.Context, cmd *cli.Command) error {
	return commandVersion(nil)
}

func cliCommandInstall(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := connectToCard()
	if err != nil {
		return err
	}
	defer cleanup()

	capFile := cmd.String("applet-file")
	if capFile == "" {
		return errors.New("you must specify a cap file path with the -a flag")
	}

	f, err := os.Open(capFile)
	if err != nil {
		return fmt.Errorf("error opening cap file: %w", err)
	}
	defer f.Close()

	i := NewInstaller(card)
	return i.Install(f, cmd.Bool("force"), cmd.Bool("keycard-applet"), cmd.Bool("cash-applet"), cmd.Bool("ndef-applet"), cmd.String("ndef"))
}

func cliCommandInfo(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := connectToCard()
	if err != nil {
		return err
	}
	defer cleanup()

	return commandInfo(card)
}

func cliCommandDelete(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := connectToCard()
	if err != nil {
		return err
	}
	defer cleanup()

	return commandDelete(card)
}

func cliCommandInit(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := connectToCard()
	if err != nil {
		return err
	}
	defer cleanup()

	return commandInit(card)
}

func cliCommandShell(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := connectToCard()
	if err != nil {
		return err
	}
	defer cleanup()

	return commandShell(card)
}

func ask(description string) string {
	r := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", description)
	text, err := r.ReadString('\n')
	if err != nil {
		stdlog.Fatal(err)
	}

	return strings.TrimSpace(text)
}

func askHex(description string) []byte {
	s := ask(description)
	if s[:2] == "0x" {
		s = s[2:]
	}

	data, err := hex.DecodeString(s)
	if err != nil {
		stdlog.Fatal(err)
	}

	return data
}

func askInt(description string) int {
	s := ask(description)
	i, err := strconv.ParseInt(s, 10, 8)
	if err != nil {
		stdlog.Fatal(err)
	}

	return int(i)
}

func commandVersion(card *scard.Card) error {
	fmt.Printf("version %+v\n", version)
	return nil
}

func commandInfo(card *scard.Card) error {
	i := NewInitializer(card)
	info, cashInfo, err := i.Info()
	if err != nil {
		return err
	}

	var keyInitialized bool
	if len(info.KeyUID) > 0 {
		keyInitialized = true
	}

	fmt.Printf("Keycard Applet:\n")
	fmt.Printf("  Installed: %+v\n", info.Installed)
	fmt.Printf("  Initialized: %+v\n", info.Initialized)
	fmt.Printf("  Key Initialized: %+v\n", keyInitialized)
	fmt.Printf("  InstanceUID: 0x%x\n", info.InstanceUID)
	fmt.Printf("  SecureChannelPublicKey: 0x%x\n", info.SecureChannelPublicKey)
	fmt.Printf("  Version: 0x%x\n", info.Version)
	fmt.Printf("  AvailableSlots: 0x%x\n", info.AvailableSlots)
	fmt.Printf("  KeyUID: 0x%x\n", info.KeyUID)
	fmt.Printf("  Capabilities:\n")
	fmt.Printf("    Secure channel:%v\n", info.HasSecureChannelCapability())
	fmt.Printf("    Key management:%v\n", info.HasKeyManagementCapability())
	fmt.Printf("    Credentials Management:%v\n", info.HasCredentialsManagementCapability())
	fmt.Printf("    NDEF:%v\n", info.HasNDEFCapability())
	fmt.Printf("Cash Applet:\n")

	if len(cashInfo.PublicKey) == 0 {
		fmt.Printf("  Installed: %+v\n", false)
		return nil
	}

	ecdsaPubKey, err := crypto.UnmarshalPubkey(cashInfo.PublicKey)
	if err != nil {
		return err
	}

	cashAddress := crypto.PubkeyToAddress(*ecdsaPubKey)

	fmt.Printf("  Installed: %+v\n", cashInfo.Installed)
	fmt.Printf("  PublicKey: 0x%x\n", cashInfo.PublicKey)
	fmt.Printf("  Address: 0x%x\n", cashAddress)
	fmt.Printf("  Public Data: 0x%x\n", cashInfo.PublicData)
	fmt.Printf("  Version: 0x%x\n", cashInfo.Version)

	return nil
}

func commandDelete(card *scard.Card) error {
	i := NewInstaller(card)
	err := i.Delete()
	if err != nil {
		return err
	}

	fmt.Printf("applet deleted\n")

	return nil
}

func commandInit(card *scard.Card) error {
	i := NewInitializer(card)
	secrets, err := i.Init()
	if err != nil {
		return err
	}

	fmt.Printf("PIN %s\n", secrets.Pin())
	fmt.Printf("PUK %s\n", secrets.Puk())
	fmt.Printf("Pairing password: %s\n", secrets.PairingPass())

	return nil
}

func commandShell(card *scard.Card) error {
	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		s := NewShell(card)
		return s.Run()
	} else {
		return errors.New("non interactive shell. you must pipe commands")
	}
}
