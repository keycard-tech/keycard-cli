package internal

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/identifiers"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
)

var installerLogger = log.New("package", "installer")

var (
	ErrAppletAlreadyInstalled = errors.New("keycard applet already installed")
)

// Installer defines a struct with methods to install applets in a card.
type Installer struct {
	c types.Channel
}

// NewInstaller returns a new Installer that communicates to Transmitter t.
func NewInstaller(t keycardio.Transmitter) *Installer {
	return &Installer{
		c: keycardio.NewNormalChannel(t),
	}
}

// Install installs the applet from the specified capFile.
func (i *Installer) Install(capFile *os.File, overwriteApplet bool, installKeycard bool, installCash bool, installNDEF bool, ndefRecordTemplate string) error {
	installerLogger.Info("installation started")
	startTime := time.Now()
	cmdSet := globalplatform.NewCommandSet(i.c)

	installerLogger.Info("check if keycard is already installed")
	if err := i.checkAppletAlreadyInstalled(cmdSet, overwriteApplet); err != nil {
		installerLogger.Error("check if keycard is already installed failed", "error", err)
		return err
	}

	installerLogger.Info("select ISD")
	err := cmdSet.Select()
	if err != nil {
		installerLogger.Error("select failed", "error", err)
		return err
	}

	installerLogger.Info("opening secure channel")
	if err = cmdSet.OpenSecureChannel(); err != nil {
		installerLogger.Error("open secure channel failed", "error", err)
		return err
	}

	installerLogger.Info("delete old version (if present)")
	if err = cmdSet.DeleteKeycardInstancesAndPackage(); err != nil {
		installerLogger.Error("delete keycard instances and package failed", "error", err)
		return err
	}

	installerLogger.Info("loading package")
	callback := func(index, total int) {
		installerLogger.Debug(fmt.Sprintf("loading %d/%d", index+1, total))
	}
	if err = cmdSet.LoadKeycardPackage(capFile, callback); err != nil {
		installerLogger.Error("load failed", "error", err)
		return err
	}

	if installKeycard {
		installerLogger.Info("installing Keycard applet")
		if err = cmdSet.InstallKeycardApplet(); err != nil {
			installerLogger.Error("installing Keycard applet failed", "error", err)
			return err
		}
	}

	if installCash {
		installerLogger.Info("installing Cash applet")
		if err = cmdSet.InstallCashApplet(); err != nil {
			installerLogger.Error("installing Cash applet failed", "error", err)
			return err
		}
	}

	if installNDEF {
		var (
			ndefURL    string
			ndefRecord []byte
		)

		if ndefRecordTemplate != "" {
			ndefURL, ndefRecord, err = i.buildNDEFRecordWithCashAppletData(ndefRecordTemplate)
			if err != nil {
				return err
			}
		}

		installerLogger.Info("setting NDEF url", "url", ndefURL)
		installerLogger.Info("re-select ISD")
		err = cmdSet.Select()
		if err != nil {
			installerLogger.Error("re-select failed", "error", err)
			return err
		}

		installerLogger.Info("re-opening secure channel")
		if err = cmdSet.OpenSecureChannel(); err != nil {
			installerLogger.Error("open secure channel failed", "error", err)
			return err
		}

		installerLogger.Info("installing NDEF applet")
		if err = cmdSet.InstallNDEFApplet(ndefRecord); err != nil {
			installerLogger.Error("installing NDEF applet failed", "error", err)
			return err
		}
	}

	elapsed := time.Since(startTime)
	installerLogger.Info(fmt.Sprintf("installation completed in %.4f seconds", elapsed.Seconds()))
	return err
}

// Delete deletes the applet from the card.
func (i *Installer) Delete() error {
	cmdSet := globalplatform.NewCommandSet(i.c)

	installerLogger.Info("select ISD")
	err := cmdSet.Select()
	if err != nil {
		installerLogger.Error("select failed", "error", err)
		return err
	}

	installerLogger.Info("opening secure channel")
	if err = cmdSet.OpenSecureChannel(); err != nil {
		installerLogger.Error("open secure channel failed", "error", err)
		return err
	}

	installerLogger.Info("delete old version")
	if err = cmdSet.DeleteKeycardInstancesAndPackage(); err != nil {
		installerLogger.Error("delete keycard instances and package failed", "error", err)
		return err
	}

	return nil
}

func (i *Installer) buildNDEFRecordWithCashAppletData(ndefRecordTemplate string) (string, []byte, error) {
	cashCmdSet := keycard.NewCashCommandSet(i.c)
	installerLogger.Info("selecting cash applet")
	err := cashCmdSet.Select()
	if err != nil {
		installerLogger.Error("error selecting cash applet", "error", err)
		return "", nil, err
	}

	info := cashCmdSet.CashApplicationInfo
	installerLogger.Info("parsing cash applet public key", "public key", fmt.Sprintf("0x%x", info.PublicKey))
	ecdsaPubKey, err := crypto.UnmarshalPubkey(info.PublicKey)
	if err != nil {
		installerLogger.Error("error parsing cash applet public key", "error", err)
		return "", nil, err
	}

	address := crypto.PubkeyToAddress(*ecdsaPubKey)
	installerLogger.Info("deriving cash applet address", "address", address.String())
	vars := map[string]string{
		"cashAddress": address.String(),
	}

	return BuildNdefDataWithURL(ndefRecordTemplate, vars)
}

func (i *Installer) checkAppletAlreadyInstalled(cmdSet *globalplatform.CommandSet, overwriteApplet bool) error {
	keycardInstanceAID, err := identifiers.KeycardInstanceAID(identifiers.KeycardDefaultInstanceIndex)
	if err != nil {
		return err
	}

	err = cmdSet.SelectAID(keycardInstanceAID)
	switch e := err.(type) {
	case *apdu.ErrBadResponse:
		// keycard applet not found, so not installed yet.
		if e.Sw == globalplatform.SwFileNotFound {
			return nil
		}
		return err
	case nil: // selected successfully, so it's already installed
		if overwriteApplet {
			return nil
		}
		return ErrAppletAlreadyInstalled
	default:
		return err
	}
}
