package internal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	keycard "github.com/keycard-tech/keycard-go/v4"
	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform"
	"github.com/keycard-tech/keycard-go/v4/identifiers"
	keycardio "github.com/keycard-tech/keycard-go/v4/io"
	"github.com/keycard-tech/keycard-go/v4/types"
)

var installerLogger = log.New("package", "installer")

var (
	ErrAppletAlreadyInstalled = errors.New("keycard applet already installed")
)

var MathPackageAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x02}

const (
	swFileExists           = 0x6A89
	swReferencedNameExists = 0x6A8A
)

func mathPackageHint() string {
	return fmt.Sprintf(
		"the keycard package depends on the keycard-math-soft library package (AID %s), which might not be loaded on the card. "+
			"Download its cap file from https://github.com/keycard-tech/keycard-math-soft and retry with --load-math PATH_TO_MATH_CAP_FILE",
		strings.ToUpper(hex.EncodeToString(MathPackageAID)),
	)
}

func withMathHint(err error, mathLoaded bool) error {
	if err == nil || mathLoaded {
		return err
	}
	return fmt.Errorf("%w\nhint: %s", err, mathPackageHint())
}

// swOf returns the status word carried by err, if any.
func swOf(err error) (uint16, bool) {
	var e *apdu.ErrBadResponse
	if errors.As(err, &e) {
		return e.Sw, true
	}
	return 0, false
}

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

// InstallOptions holds the parameters for [Installer.Install].
type InstallOptions struct {
	CapFile *os.File
	MathCapFile *os.File
	OverwriteApplet bool
	InstallKeycard  bool
	InstallIdent    bool
	InstallCash     bool
	InstallNDEF     bool
	NDEFRecordTemplate string
}

func (i *Installer) Install(opts *InstallOptions) error {
	installerLogger.Info("installation started")
	startTime := time.Now()
	cmdSet := globalplatform.NewCommandSet(i.c)

	mathLoaded := opts.MathCapFile != nil

	installerLogger.Info("check if keycard is already installed")
	if err := i.checkAppletAlreadyInstalled(cmdSet, opts.OverwriteApplet); err != nil {
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

	if opts.MathCapFile != nil {
		if err = i.loadMathPackage(cmdSet, opts.MathCapFile); err != nil {
			return err
		}
	}

	installerLogger.Info("loading package")
	callback := func(index, total int) {
		installerLogger.Debug(fmt.Sprintf("loading %d/%d", index+1, total))
	}
	if err = cmdSet.LoadKeycardPackage(opts.CapFile, callback); err != nil {
		installerLogger.Error("load failed", "error", err)
		return withMathHint(err, mathLoaded)
	}

	if opts.InstallKeycard {
		installerLogger.Info("installing Keycard applet")
		if err = cmdSet.InstallKeycardApplet(); err != nil {
			installerLogger.Error("installing Keycard applet failed", "error", err)
			return withMathHint(err, mathLoaded)
		}
	}

	if opts.InstallIdent {
		installerLogger.Info("installing Ident applet")
		if err = cmdSet.InstallIdentApplet(); err != nil {
			installerLogger.Error("installing Ident applet failed", "error", err)
			return withMathHint(err, mathLoaded)
		}
	}

	if opts.InstallCash {
		installerLogger.Info("installing Cash applet")
		if err = cmdSet.InstallCashApplet(); err != nil {
			installerLogger.Error("installing Cash applet failed", "error", err)
			return withMathHint(err, mathLoaded)
		}
	}

	if opts.InstallNDEF {
		var (
			ndefURL    string
			ndefRecord []byte
		)

		if opts.NDEFRecordTemplate != "" {
			ndefURL, ndefRecord, err = i.buildNDEFRecordWithCashAppletData(opts.NDEFRecordTemplate)
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
			return withMathHint(err, mathLoaded)
		}
	}

	elapsed := time.Since(startTime)
	installerLogger.Info(fmt.Sprintf("installation completed in %.4f seconds", elapsed.Seconds()))
	return err
}

func (i *Installer) Delete(removeMath bool) error {
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

	if removeMath {
		if err = i.deleteMathPackage(cmdSet); err != nil {
			return err
		}
	}

	return nil
}

func (i *Installer) loadMathPackage(cmdSet *globalplatform.CommandSet, capFile *os.File) error {
	installerLogger.Info("loading math package", "aid", mathPackageAIDString(), "cap", capFile.Name())

	callback := func(index, total int) {
		installerLogger.Debug(fmt.Sprintf("loading math package %d/%d", index+1, total))
	}

	if err := cmdSet.LoadPackage(capFile, MathPackageAID, callback); err != nil {
		if sw, ok := swOf(err); ok && (sw == swFileExists || sw == swReferencedNameExists) {
			installerLogger.Info("math package already loaded, skipping")
			return nil
		}
		installerLogger.Error("loading math package failed", "error", err)
		return fmt.Errorf("loading math package: %w", err)
	}

	return nil
}

func (i *Installer) deleteMathPackage(cmdSet *globalplatform.CommandSet) error {
	installerLogger.Info("deleting math package", "aid", mathPackageAIDString())

	if err := cmdSet.DeleteObject(MathPackageAID); err != nil {
		if sw, ok := swOf(err); ok && (sw == globalplatform.SwFileNotFound || sw == globalplatform.SwReferencedDataNotFound) {
			installerLogger.Info("math package not present, nothing to delete")
			return nil
		}
		installerLogger.Error("deleting math package failed", "error", err)
		return fmt.Errorf("deleting math package: %w", err)
	}

	return nil
}

func mathPackageAIDString() string {
	return strings.ToUpper(hex.EncodeToString(MathPackageAID))
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
