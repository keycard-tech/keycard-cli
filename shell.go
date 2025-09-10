package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
)

type shellCommand = func(args ...string) error

type TemplateFuncs struct {
	s *Shell
}

func (t *TemplateFuncs) FuncMap() template.FuncMap {
	return template.FuncMap{
		"env":                      t.Env,
		"session_pairing_key":      t.SessionPairingKey,
		"session_pairing_index":    t.SessionPairingIndex,
		"session_pin":              t.SessionPIN,
		"session_puk":              t.SessionPUK,
		"session_pairing_password": t.SessionPairingPassword,
	}
}

func (t *TemplateFuncs) Env(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("env variable is empty: %s", name)
	}

	return value, nil
}

func (t *TemplateFuncs) SessionPairingKey() (string, error) {
	if t.s.kCmdSet.PairingInfo == nil {
		return "", errors.New("pairing key not known")
	}

	return fmt.Sprintf("%x", t.s.kCmdSet.PairingInfo.Key), nil
}

func (t *TemplateFuncs) SessionPairingIndex() (string, error) {
	if t.s.kCmdSet.PairingInfo == nil {
		return "", errors.New("pairing index not known")
	}

	return fmt.Sprintf("%d", t.s.kCmdSet.PairingInfo.Index), nil
}

func (t *TemplateFuncs) SessionPIN() (string, error) {
	if t.s.Secrets == nil {
		return "", errors.New("pin is not set")
	}

	return t.s.Secrets.Pin(), nil
}

func (t *TemplateFuncs) SessionPUK() (string, error) {
	if t.s.Secrets == nil {
		return "", errors.New("puk is not set")
	}

	return t.s.Secrets.Puk(), nil
}

func (t *TemplateFuncs) SessionPairingPassword() (string, error) {
	if t.s.Secrets == nil {
		return "", errors.New("pairing password is not set")
	}

	return t.s.Secrets.PairingPass(), nil
}

type Shell struct {
	t          keycardio.Transmitter
	c          types.Channel
	Secrets    *keycard.Secrets
	gpCmdSet   *globalplatform.CommandSet
	kCmdSet    *keycard.CommandSet
	cashCmdSet *keycard.CashCommandSet
	commands   map[string]shellCommand
	out        *bytes.Buffer
	tplFuncMap template.FuncMap
}

func NewShell(t keycardio.Transmitter) *Shell {
	c := keycardio.NewNormalChannel(t)

	s := &Shell{
		t:          t,
		c:          c,
		kCmdSet:    keycard.NewCommandSet(c),
		cashCmdSet: keycard.NewCashCommandSet(c),
		gpCmdSet:   globalplatform.NewCommandSet(c),
		out:        new(bytes.Buffer),
	}

	tplFuncs := &TemplateFuncs{s}
	s.tplFuncMap = tplFuncs.FuncMap()

	s.commands = map[string]shellCommand{
		"echo":                          s.commandEcho,
		"gp-send-apdu":                  s.commandGPSendAPDU,
		"gp-select":                     s.commandGPSelect,
		"gp-open-secure-channel":        s.commandGPOpenSecureChannel,
		"gp-delete":                     s.commandGPDelete,
		"gp-load":                       s.commandGPLoad,
		"gp-install-for-install":        s.commandGPInstallForInstall,
		"gp-get-status":                 s.commandGPGetStatus,
		"keycard-init":                  s.commandKeycardInit,
		"keycard-select":                s.commandKeycardSelect,
		"keycard-pair":                  s.commandKeycardPair,
		"keycard-unpair":                s.commandKeycardUnpair,
		"keycard-open-secure-channel":   s.commandKeycardOpenSecureChannel,
		"keycard-get-status":            s.commandKeycardGetStatus,
		"keycard-set-secrets":           s.commandKeycardSetSecrets,
		"keycard-set-pairing":           s.commandKeycardSetPairing,
		"keycard-verify-pin":            s.commandKeycardVerifyPIN,
		"keycard-change-pin":            s.commandKeycardChangePIN,
		"keycard-change-puk":            s.commandKeycardChangePUK,
		"keycard-unblock-pin":           s.commandKeycardUnblockPin,
		"keycard-change-pairing-secret": s.commandKeycardChangePairingSecret,
		"keycard-generate-key":          s.commandKeycardGenerateKey,
		"keycard-remove-key":            s.commandKeycardRemoveKey,
		"keycard-derive-key":            s.commandKeycardDeriveKey,
		"keycard-export-key-private":    s.commandKeycardExportKeyPrivate,
		"keycard-export-key-public":     s.commandKeycardExportKeyPublic,
		"keycard-sign":                  s.commandKeycardSign,
		"keycard-sign-with-path":        s.commandKeycardSignWithPath,
		"keycard-sign-message":          s.commandKeycardSignMessage,
		"keycard-sign-pinless":          s.commandKeycardSignPinless,
		"keycard-sign-message-pinless":  s.commandKeycardSignMessagePinless,
		"keycard-set-pinless-path":      s.commandKeycardSetPinlessPath,
		"keycard-load-seed":             s.commandKeycardLoadSeed,
		"keycard-generate-mnemonic":     s.commandKeycardGenerateMnemonic,
		"keycard-identify":              s.commandKeycardIdentify,
		"cash-select":                   s.commandCashSelect,
		"cash-sign":                     s.commandCashSign,
	}

	return s
}

func (s *Shell) write(str string) {
	s.out.WriteString(str)
}

func (s *Shell) flushOut() {
	io.Copy(os.Stdout, s.out)
}

func (s *Shell) Run() error {
	reader := bufio.NewReader(os.Stdin)
	defer s.flushOut()

	for {
		line, readErr := reader.ReadString('\n')

		if readErr != nil && readErr != io.EOF {
			break
		}

		err := s.evalLine(line)
		if err != nil {
			return err
		}

		if readErr == io.EOF {
			break
		}
	}

	return nil
}

func (s *Shell) commandEcho(args ...string) error {
	fmt.Printf("> %s\n", strings.Join(args, " "))
	return nil
}

func (s *Shell) commandGPSendAPDU(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	rawCmd, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}

	cmd, err := apdu.ParseCommand(rawCmd)
	if err != nil {
		logger.Error("error parsing command", "error", err)
		return err
	}

	var channel types.Channel

	if sc := s.gpCmdSet.SecureChannel(); sc != nil {
		channel = sc
	} else {
		channel = s.gpCmdSet.Channel()
	}

	logger.Info(fmt.Sprintf("send apdu %x", rawCmd))
	resp, err := channel.Send(cmd)
	if err != nil {
		logger.Error("send apdu failed", "error", err)
		return err
	}

	if resp.Sw != apdu.SwOK {
		logger.Error("unexpected response", "sw", fmt.Sprintf("%x", resp.Sw))
		return apdu.NewErrBadResponse(resp.Sw, "unexpected response")
	}

	return nil
}

func (s *Shell) commandGPSelect(args ...string) error {
	if err := s.requireArgs(args, 0, 1); err != nil {
		return err
	}

	if len(args) == 0 {
		logger.Info("select ISD")
		return s.gpCmdSet.Select()
	}

	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("select AID %x", aid))
	return s.gpCmdSet.SelectAID(aid)
}

func (s *Shell) commandGPOpenSecureChannel(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("open secure channel")
	return s.gpCmdSet.OpenSecureChannel()
}

func (s *Shell) commandGPDelete(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("delete %x", aid))

	return s.gpCmdSet.DeleteObject(aid)
}

func (s *Shell) commandGPLoad(args ...string) error {
	if err := s.requireArgs(args, 2); err != nil {
		return err
	}

	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()

	pkgAID, err := hex.DecodeString(args[1])
	if err != nil {
		return err
	}

	logger.Info("load package")
	callback := func(index, total int) {
		logger.Debug(fmt.Sprintf("loading %d/%d", index+1, total))
	}
	if err = s.gpCmdSet.LoadPackage(f, pkgAID, callback); err != nil {
		logger.Error("load failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandGPInstallForInstall(args ...string) error {
	if err := s.requireArgs(args, 3, 4); err != nil {
		return err
	}

	pkgAID, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}

	appletAID, err := hex.DecodeString(args[1])
	if err != nil {
		return err
	}

	instanceAID, err := hex.DecodeString(args[2])
	if err != nil {
		return err
	}

	var params []byte

	if len(args) == 4 {
		params, err = hex.DecodeString(args[3])
		if err != nil {
			return err
		}
	}

	logger.Info("install for install", "pkg", fmt.Sprintf("%x", pkgAID), "applet", fmt.Sprintf("%x", appletAID), "instance", fmt.Sprintf("%x", instanceAID), "params", fmt.Sprintf("%x", params))

	return s.gpCmdSet.InstallForInstall(pkgAID, appletAID, instanceAID, params)
}

func (s *Shell) commandGPGetStatus(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("get status")
	cardStatus, err := s.gpCmdSet.GetStatus()
	if err != nil {
		logger.Error("get status failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("CARD STATUS: %s\n\n", cardStatus.LifeCycle()))

	return nil
}

func (s *Shell) commandKeycardInit(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	if s.kCmdSet.ApplicationInfo == nil {
		return errors.New("keycard applet not selected")
	}

	if !s.kCmdSet.ApplicationInfo.Installed {
		return errAppletNotInstalled
	}

	if s.kCmdSet.ApplicationInfo.Initialized {
		return errCardAlreadyInitialized
	}

	if s.Secrets == nil {
		secrets, err := keycard.GenerateSecrets()
		if err != nil {
			logger.Error("secrets generation failed", "error", err)
			return err
		}

		s.Secrets = secrets
	}

	logger.Info("initializing")
	err := s.kCmdSet.Init(s.Secrets)
	if err != nil {
		logger.Error("initialization failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("PIN: %s\n", s.Secrets.Pin()))
	s.write(fmt.Sprintf("PUK: %s\n", s.Secrets.Puk()))
	s.write(fmt.Sprintf("PAIRING PASSWORD: %s\n\n", s.Secrets.PairingPass()))

	return nil
}

func (s *Shell) commandKeycardSetSecrets(args ...string) error {
	if err := s.requireArgs(args, 3); err != nil {
		return err
	}

	s.Secrets = keycard.NewSecrets(args[0], args[1], args[2])

	return nil
}

func (s *Shell) commandKeycardSelect(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("select keycard")
	err := s.kCmdSet.Select()
	info := s.kCmdSet.ApplicationInfo

	var keyInitialized bool
	if len(info.KeyUID) > 0 {
		keyInitialized = true
	}

	s.write(fmt.Sprintf("Installed: %+v\n", info.Installed))
	s.write(fmt.Sprintf("Initialized: %+v\n", info.Initialized))
	s.write(fmt.Sprintf("Key Initialized: %+v\n", keyInitialized))
	s.write(fmt.Sprintf("InstanceUID: %x\n", info.InstanceUID))
	s.write(fmt.Sprintf("SecureChannelPublicKey: %x\n", info.SecureChannelPublicKey))
	s.write(fmt.Sprintf("Version: %x\n", info.Version))
	s.write(fmt.Sprintf("AvailableSlots: %x\n", info.AvailableSlots))
	s.write(fmt.Sprintf("KeyUID: %x\n", info.KeyUID))
	s.write(fmt.Sprintf("Capabilities:\n"))
	s.write(fmt.Sprintf("  Secure channel:%v\n", info.HasSecureChannelCapability()))
	s.write(fmt.Sprintf("  Key management:%v\n", info.HasKeyManagementCapability()))
	s.write(fmt.Sprintf("  Credentials Management:%v\n", info.HasCredentialsManagementCapability()))
	s.write(fmt.Sprintf("  NDEF:%v\n\n", info.HasNDEFCapability()))

	if e, ok := err.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
		logger.Error("select keycard failed", "error", err)
		return ErrNotInstalled
	}

	return err
}

func (s *Shell) commandKeycardPair(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	if s.Secrets == nil {
		return errors.New("cannot pair without setting secrets")
	}

	logger.Info("pair")
	err := s.kCmdSet.Pair(s.Secrets.PairingPass())
	if err != nil {
		logger.Error("pair failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("PAIRING KEY: %x\n", s.kCmdSet.PairingInfo.Key))
	s.write(fmt.Sprintf("PAIRING INDEX: %v\n\n", s.kCmdSet.PairingInfo.Index))

	return nil
}

func (s *Shell) commandKeycardUnpair(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	indexInt, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return err
	}

	index := uint8(indexInt)

	if s.Secrets == nil {
		return errors.New("cannot unpair without setting secrets")
	}

	logger.Info(fmt.Sprintf("unpair index %d", index))
	err = s.kCmdSet.Unpair(index)
	if err != nil {
		logger.Error("unpair failed", "error", err)
		return err
	}

	s.write("UNPAIRED\n\n")

	return nil
}

func (s *Shell) commandKeycardSetPairing(args ...string) error {
	if err := s.requireArgs(args, 2); err != nil {
		return err
	}

	key, err := s.parseHex(args[0])
	if err != nil {
		return err
	}

	index, err := strconv.ParseInt(args[1], 10, 8)
	if err != nil {
		return err
	}

	s.kCmdSet.SetPairingInfo(key, int(index))

	return nil
}

func (s *Shell) commandKeycardOpenSecureChannel(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	if s.kCmdSet.PairingInfo == nil {
		return errors.New("cannot open secure channel without setting pairing info")
	}

	logger.Info("open keycard secure channel")
	if err := s.kCmdSet.OpenSecureChannel(); err != nil {
		logger.Error("open keycard secure channel failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardGetStatus(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("get status application")
	appStatus, err := s.kCmdSet.GetStatusApplication()
	if err != nil {
		logger.Error("get status application failed", "error", err)
		return err
	}

	logger.Info("get status key path")
	keyStatus, err := s.kCmdSet.GetStatusKeyPath()
	if err != nil {
		logger.Error("get status key path failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("STATUS - PIN RETRY COUNT: %d\n", appStatus.PinRetryCount))
	s.write(fmt.Sprintf("STATUS - PUK RETRY COUNT: %d\n", appStatus.PUKRetryCount))
	s.write(fmt.Sprintf("STATUS - KEY INITIALIZED: %v\n", appStatus.KeyInitialized))
	s.write(fmt.Sprintf("STATUS - KEY PATH: %v\n\n", keyStatus.Path))

	return nil
}

func (s *Shell) commandKeycardVerifyPIN(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info("verify PIN")
	if err := s.kCmdSet.VerifyPIN(args[0]); err != nil {
		logger.Error("verify PIN failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardChangePIN(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info("change PIN")
	if err := s.kCmdSet.ChangePIN(args[0]); err != nil {
		logger.Error("change PIN failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardChangePUK(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info("change PUK")
	if err := s.kCmdSet.ChangePUK(args[0]); err != nil {
		logger.Error("change PUK failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardUnblockPin(args ...string) error {
	if err := s.requireArgs(args, 2); err != nil {
		return err
	}

	logger.Info("unblock PIN")
	if err := s.kCmdSet.UnblockPIN(args[0], args[1]); err != nil {
		logger.Error("unblock PIN failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardChangePairingSecret(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info("change pairing secret")
	if err := s.kCmdSet.ChangePairingSecret(args[0]); err != nil {
		logger.Error("change pairing secret failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardGenerateKey(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("get status before generating key")
	appStatus, err := s.kCmdSet.GetStatusApplication()
	if err != nil {
		logger.Error("get status failed", "error", err)
		return err
	}

	if appStatus.KeyInitialized {
		err = errors.New("key already generated. you must delete it before creating a new one")
		logger.Error("generate key failed", "error", err)
		return err
	}

	logger.Info("generate key")
	keyUID, err := s.kCmdSet.GenerateKey()
	if err != nil {
		return err
	}

	s.write(fmt.Sprintf("KEY UID %x\n\n", keyUID))

	return nil
}

func (s *Shell) commandKeycardRemoveKey(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("remove key")
	err := s.kCmdSet.RemoveKey()
	if err != nil {
		return err
	}

	s.write(fmt.Sprintf("KEY REMOVED \n\n"))

	return nil
}

func (s *Shell) commandKeycardDeriveKey(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("derive key %s", args[0]))
	if err := s.kCmdSet.DeriveKey(args[0]); err != nil {
		logger.Error("derive key failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardExportKeyPrivate(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("export key %s", args[0]))
	privKey, pubKey, err := s.kCmdSet.ExportKey(true, false, false, args[0])
	if err != nil {
		logger.Error("export key failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("EXPORTED PRIVATE KEY\n%x\n", privKey))
	s.write(fmt.Sprintf("EXPORTED PUBLIC KEY\n%x\n\n", pubKey))

	return nil
}

func (s *Shell) commandKeycardExportKeyPublic(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("export key %s", args[0]))
	privKey, pubKey, err := s.kCmdSet.ExportKey(true, false, true, args[0])
	if err != nil {
		logger.Error("export key failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("EXPORTED PRIVATE KEY\n%x\n", privKey))
	s.write(fmt.Sprintf("EXPORTED PUBLIC KEY\n%x\n\n", pubKey))

	return nil
}

func (s *Shell) commandKeycardSign(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	data, err := s.parseHex(args[0])
	if err != nil {
		logger.Error("failed parsing hex data", "error", err)
		return err
	}

	logger.Info("sign")
	sig, err := s.kCmdSet.Sign(data)
	if err != nil {
		logger.Error("sign failed", "error", err)
		return err
	}

	s.writeSignatureInfo(sig)

	return nil
}

func (s *Shell) commandKeycardSignWithPath(args ...string) error {
	if err := s.requireArgs(args, 2); err != nil {
		return err
	}

	data, err := s.parseHex(args[0])
	if err != nil {
		logger.Error("failed parsing hex data", "error", err)
		return err
	}

	logger.Info("sign with path")
	sig, err := s.kCmdSet.SignWithPath(data, args[1])
	if err != nil {
		logger.Error("sign with path failed", "error", err)
		return err
	}

	s.writeSignatureInfo(sig)

	return nil
}

func (s *Shell) commandKeycardSignMessage(args ...string) error {
	if len(args) < 1 {
		return errors.New("keycard-sign-message require at least 1 parameter")
	}

	originalMessage := strings.Join(args, " ")
	hash := hashEthereumMessage(originalMessage)

	logger.Info("sign message")
	sig, err := s.kCmdSet.Sign(hash)
	if err != nil {
		logger.Error("sign message failed", "error", err)
		return err
	}

	s.writeSignatureInfo(sig)

	return nil
}

func (s *Shell) commandKeycardSignPinless(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	data, err := s.parseHex(args[0])
	if err != nil {
		logger.Error("failed parsing hex data", "error", err)
		return err
	}

	logger.Info("sign pinless")
	sig, err := s.kCmdSet.SignPinless(data)
	if err != nil {
		logger.Error("sign pinless failed", "error", err)
		return err
	}

	s.writeSignatureInfo(sig)

	return nil
}

func (s *Shell) commandKeycardSignMessagePinless(args ...string) error {
	if len(args) < 1 {
		return errors.New("keycard-sign-message-pinless require at least 1 parameter")
	}

	originalMessage := strings.Join(args, " ")
	hash := hashEthereumMessage(originalMessage)

	logger.Info("sign message pinless")
	sig, err := s.kCmdSet.SignPinless(hash)
	if err != nil {
		logger.Error("sign message pinless failed", "error", err)
		return err
	}

	s.writeSignatureInfo(sig)

	return nil
}

func (s *Shell) commandKeycardSetPinlessPath(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("set pinless path %s", args[0]))
	if err := s.kCmdSet.SetPinlessPath(args[0]); err != nil {
		logger.Error("set pinless path failed", "error", err)
		return err
	}

	return nil
}

func (s *Shell) commandKeycardGenerateMnemonic(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	checksumSize, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		logger.Error("failed parsing checksum size", "error", err)
		return err
	}

	logger.Info("generate mnemonic", "checksumSize", checksumSize)
	indexes, err := s.kCmdSet.GenerateMnemonic(int(checksumSize))
	if err != nil {
		logger.Error("generate mnemonic failed", "error", err)
		return err
	}

	s.write(fmt.Sprintf("MNEMONIC INDEXES %v\n\n", indexes))

	return nil
}

func (s *Shell) commandKeycardLoadSeed(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	seed, err := s.parseHex(args[0])
	if err != nil {
		logger.Error("failed parsing seed data", "error", err)
		return err
	}

	logger.Info("loading seed", "seed", fmt.Sprintf("%x", seed))
	keyID, err := s.kCmdSet.LoadSeed(seed)
	if err != nil {
		logger.Error("load seed failed", "error", err)
		return err
	}

	logger.Info(fmt.Sprintf("key ID %x", keyID))

	return nil
}

func (s *Shell) commandKeycardIdentify(args ...string) error {
	pubkey, err := s.kCmdSet.Identify()

	if err != nil {
		logger.Error("failed card identification", "error", err)
		return err
	}

	logger.Info(fmt.Sprintf("identification public key: %x", pubkey))

	var compareKey []byte
	if len(args) == 1 {
		compareKey, err = s.parseHex(args[0])

		if err != nil {
			logger.Error("failed parsing public key", "error", err)
			return err
		}
	} else {
		compareKey = pubkey
	}

	if !bytes.Equal(compareKey, pubkey) {
		logger.Error("the recovered key does not match the expected value", "error", err)
		return errors.New("genuinity check failed")
	}

	return nil
}

func (s *Shell) commandCashSelect(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}

	logger.Info("select cash")
	err := s.cashCmdSet.Select()
	info := s.cashCmdSet.CashApplicationInfo

	s.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	s.write(fmt.Sprintf("PublicKey: %x\n", info.PublicKey))
	s.write(fmt.Sprintf("PublicData: %x\n", info.PublicData))
	s.write(fmt.Sprintf("Version: %x\n\n", info.Version))

	if e, ok := err.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
		logger.Error("select cash failed", "error", err)
		return ErrCashNotInstalled
	}

	return err
}

func (s *Shell) commandCashSign(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}

	data, err := s.parseHex(args[0])
	if err != nil {
		logger.Error("failed parsing hex data", "error", err)
		return err
	}

	logger.Info("sign")
	sig, err := s.cashCmdSet.Sign(data)
	if err != nil {
		logger.Error("sign failed", "error", err)
		return err
	}

	s.writeSignatureInfo(sig)

	return nil
}

func (s *Shell) requireArgs(args []string, possibleArgsN ...int) error {
	for _, n := range possibleArgsN {
		if len(args) == n {
			return nil
		}
	}

	ns := make([]string, len(possibleArgsN))
	for i, n := range possibleArgsN {
		ns[i] = fmt.Sprintf("%d", n)
	}

	return fmt.Errorf("wrong number of argument. got: %d, expected: %v", len(args), strings.Join(ns, " | "))
}

func (s *Shell) evalLine(rawLine string) error {
	line := strings.TrimSpace(rawLine)

	if len(line) == 0 || strings.HasPrefix(line, "#") {
		return nil
	}

	line, err := s.evalTemplate(line)
	if err != nil {
		return err
	}

	reg := regexp.MustCompile("\\s+")
	parts := reg.Split(line, -1)
	if cmd, ok := s.commands[parts[0]]; ok {
		return cmd(parts[1:]...)
	}

	return fmt.Errorf("command not found: %s", parts[0])
}

func (s *Shell) parseHex(str string) ([]byte, error) {
	if str[:2] == "0x" {
		str = str[2:]
	}

	return hex.DecodeString(str)
}

func (s *Shell) evalTemplate(text string) (string, error) {
	tpl, err := template.New("").Funcs(s.tplFuncMap).Parse(text)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBufferString("")
	err = tpl.Execute(buf, nil)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (s *Shell) writeSignatureInfo(sig *types.Signature) {
	ethSig := append(sig.R(), sig.S()...)
	ethSig = append(ethSig, []byte{sig.V() + 27}...)
	ecdsaPubKey, err := crypto.UnmarshalPubkey(sig.PubKey())
	if err != nil {
		log.Fatal(err)
	}

	address := crypto.PubkeyToAddress(*ecdsaPubKey)

	s.write(fmt.Sprintf("SIGNATURE R: %x\n", sig.R()))
	s.write(fmt.Sprintf("SIGNATURE S: %x\n", sig.S()))
	s.write(fmt.Sprintf("SIGNATURE V: %x\n", sig.V()))
	s.write(fmt.Sprintf("ETH SIGNATURE: 0x%x\n", ethSig))
	s.write(fmt.Sprintf("PUBLIC KEY: 0x%x\n", sig.PubKey()))
	s.write(fmt.Sprintf("ADDRESS: %s\n\n", address.String()))
}

func hashEthereumMessage(message string) []byte {
	data := []byte(message)
	if strings.HasPrefix(message, "0x") {
		if value, err := hex.DecodeString(message[2:]); err == nil {
			data = value
		}
	}

	wrappedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(wrappedMessage))
}
