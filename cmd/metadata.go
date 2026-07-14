package cmd

import (
	"context"
	"fmt"

	keycard "github.com/status-im/keycard-go"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// MetadataCommands returns the metadata management command group.
func MetadataCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "get-name",
			Usage:  "Get the card's display name",
			Action: cmdGetName,
		},
		{
			Name:  "set-name",
			Usage: "Set the card's display name",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "name",
					Usage:    "Display name for the card",
					Required: true,
				},
			},
			Action: cmdSetName,
		},
	}
}

func cmdGetName(ctx context.Context, cmd *cli.Command) error {
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

	data, err := kc.GetData(keycard.P1StoreDataPublic)
	if err != nil {
		return err
	}

	metadata, err := types.ParseMetadata(data)
	if err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	name := metadata.Name()
	if cmd.Bool("json") {
		return internal.PrintJSON(map[string]string{
			"name": name,
		})
	}

	fmt.Printf("Card name: %s\n", name)
	return nil
}

func cmdSetName(ctx context.Context, cmd *cli.Command) error {
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

	name := cmd.String("name")

	// Try to get existing metadata first
	var metadata *types.Metadata
	existingData, err := kc.GetData(keycard.P1StoreDataPublic)
	if err == nil {
		metadata, err = types.ParseMetadata(existingData)
		if err != nil {
			metadata = types.EmptyMetadata()
		}
	} else {
		metadata = types.EmptyMetadata()
	}

	if err := metadata.SetName(name); err != nil {
		return err
	}

	data := metadata.Serialize()
	if err := kc.StoreData(keycard.P1StoreDataPublic, data); err != nil {
		return err
	}

	fmt.Printf("Card name set: %s\n", name)
	return nil
}
