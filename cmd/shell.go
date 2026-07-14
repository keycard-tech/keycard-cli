package cmd

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/ebfe/scard"
	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// ShellCommand returns the shell (scripting) command.
func ShellCommand() *cli.Command {
	return &cli.Command{
		Name:  "shell",
		Usage: "Start interactive shell or run a script file",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "Path to script file (reads from stdin if omitted)",
			},
		},
		Action: cmdShell,
	}
}

func cmdShell(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	scriptFile := cmd.String("file")
	if scriptFile != "" {
		f, err := os.Open(scriptFile)
		if err != nil {
			return fmt.Errorf("error opening script file: %w", err)
		}
		defer f.Close()
		return runShell(card, f)
	}

	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return runShell(card, os.Stdin)
	}

	return errors.New("non-interactive shell. You must pipe commands or use -f flag")
}

func runShell(card *scard.Card, input io.Reader) error {
	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)
	cashKC := keycard.NewCashCommandSet(ch)
	gp := globalplatform.NewCommandSet(ch)

	shell := &shellRunner{
		ch:     ch,
		kc:     kc,
		cashKC: cashKC,
		gp:     gp,
		out:    new(bytes.Buffer),
	}

	reader := bufio.NewReader(input)
	defer shell.flushOut()

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			break
		}

		err := shell.evalLine(line)
		if err != nil {
			return err
		}

		if readErr == io.EOF {
			break
		}
	}

	return nil
}

type shellCommand = func(args ...string) error

type shellRunner struct {
	ch       types.Channel
	kc       *keycard.CommandSet
	cashKC   *keycard.CashCommandSet
	gp       *globalplatform.CommandSet
	secrets  *keycard.Secrets
	commands map[string]shellCommand
	out      *bytes.Buffer
}

func (s *shellRunner) write(str string) {
	s.out.WriteString(str)
}

func (s *shellRunner) flushOut() {
	io.Copy(os.Stdout, s.out)
}

func (s *shellRunner) initCommands() {
	if s.commands != nil {
		return
	}
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
}

func (s *shellRunner) evalLine(rawLine string) error {
	s.initCommands()

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

func (s *shellRunner) evalTemplate(text string) (string, error) {
	funcMap := template.FuncMap{
		"env": func(name string) (string, error) {
			value := os.Getenv(name)
			if value == "" {
				return "", fmt.Errorf("env variable is empty: %s", name)
			}
			return value, nil
		},
		"session_pairing_key": func() (string, error) {
			pairing := s.kc.Pairing()
			if pairing == nil {
				return "", errors.New("pairing key not known")
			}
			key := pairing.Key()
			return fmt.Sprintf("%x", key[:]), nil
		},
		"session_pairing_index": func() (string, error) {
			pairing := s.kc.Pairing()
			if pairing == nil {
				return "", errors.New("pairing index not known")
			}
			return fmt.Sprintf("%d", pairing.Index()), nil
		},
		"session_pin": func() (string, error) {
			if s.secrets == nil {
				return "", errors.New("pin is not set")
			}
			return s.secrets.Pin(), nil
		},
		"session_puk": func() (string, error) {
			if s.secrets == nil {
				return "", errors.New("puk is not set")
			}
			return s.secrets.Puk(), nil
		},
		"session_pairing_password": func() (string, error) {
			if s.secrets == nil {
				return "", errors.New("pairing password is not set")
			}
			return s.secrets.PairingPass(), nil
		},
	}

	tpl, err := template.New("").Funcs(funcMap).Parse(text)
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

func (s *shellRunner) requireArgs(args []string, possibleArgsN ...int) error {
	for _, n := range possibleArgsN {
		if len(args) == n {
			return nil
		}
	}
	ns := make([]string, len(possibleArgsN))
	for i, n := range possibleArgsN {
		ns[i] = fmt.Sprintf("%d", n)
	}
	return fmt.Errorf("wrong number of arguments. got: %d, expected: %v", len(args), strings.Join(ns, " | "))
}

func (s *shellRunner) parseHex(str string) ([]byte, error) {
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
	}
	return hex.DecodeString(str)
}

func (s *shellRunner) writeSignatureInfo(sig *types.Signature) {
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

// Shell command implementations (ported from old shell.go)
func (s *shellRunner) commandEcho(args ...string) error {
	fmt.Printf("> %s\n", strings.Join(args, " "))
	return nil
}

func (s *shellRunner) commandGPSendAPDU(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	rawCmd, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	cmd, err := apdu.ParseCommand(rawCmd)
	if err != nil {
		return err
	}
	var channel types.Channel
	if sc := s.gp.SecureChannel(); sc != nil {
		channel = sc
	} else {
		channel = s.gp.Channel()
	}
	resp, err := channel.Send(cmd)
	if err != nil {
		return err
	}
	if resp.Sw != apdu.SwOK {
		return apdu.NewErrBadResponse(resp.Sw, "unexpected response")
	}
	return nil
}

func (s *shellRunner) commandGPSelect(args ...string) error {
	if err := s.requireArgs(args, 0, 1); err != nil {
		return err
	}
	if len(args) == 0 {
		return s.gp.Select()
	}
	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	return s.gp.SelectAID(aid)
}

func (s *shellRunner) commandGPOpenSecureChannel(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	return s.gp.OpenSecureChannel()
}

func (s *shellRunner) commandGPDelete(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	return s.gp.DeleteObject(aid)
}

func (s *shellRunner) commandGPLoad(args ...string) error {
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
	callback := func(index, total int) {}
	return s.gp.LoadPackage(f, pkgAID, callback)
}

func (s *shellRunner) commandGPInstallForInstall(args ...string) error {
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
	return s.gp.InstallForInstall(pkgAID, appletAID, instanceAID, params)
}

func (s *shellRunner) commandGPGetStatus(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	cardStatus, err := s.gp.GetStatus()
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("CARD STATUS: %s\n\n", cardStatus.LifeCycle()))
	return nil
}

func (s *shellRunner) commandKeycardInit(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	if s.kc.AppInfo() == nil || !s.kc.AppInfo().Installed {
		return errors.New("keycard applet not installed")
	}
	if s.kc.AppInfo().Initialized {
		return errors.New("card already initialized")
	}
	if s.secrets == nil {
		secrets, err := keycard.GenerateSecrets()
		if err != nil {
			return err
		}
		s.secrets = secrets
	}
	if err := s.kc.Init(s.secrets); err != nil {
		return err
	}
	s.write(fmt.Sprintf("PIN: %s\n", s.secrets.Pin()))
	s.write(fmt.Sprintf("PUK: %s\n", s.secrets.Puk()))
	s.write(fmt.Sprintf("PAIRING PASSWORD: %s\n\n", s.secrets.PairingPass()))
	return nil
}

func (s *shellRunner) commandKeycardSetSecrets(args ...string) error {
	if err := s.requireArgs(args, 3); err != nil {
		return err
	}
	s.secrets = keycard.NewSecrets(args[0], args[1], args[2])
	return nil
}

func (s *shellRunner) commandKeycardSelect(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	if err := s.kc.Select(); err != nil {
		return err
	}
	info := s.kc.AppInfo()
	s.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	s.write(fmt.Sprintf("Initialized: %v\n", info.Initialized))
	s.write(fmt.Sprintf("Key Initialized: %v\n", len(info.KeyUID) > 0))
	s.write(fmt.Sprintf("Version: %x\n", info.AppVersion()))
	s.write(fmt.Sprintf("KeyUID: %x\n\n", info.KeyUID))
	return nil
}

func (s *shellRunner) commandKeycardPair(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	if s.secrets == nil {
		return errors.New("cannot pair without setting secrets")
	}
	if err := s.kc.Pair(s.secrets.PairingPass()); err != nil {
		return err
	}
	pairing := s.kc.Pairing()
	key := pairing.Key()
	s.write(fmt.Sprintf("PAIRING KEY: %x\n", key[:]))
	s.write(fmt.Sprintf("PAIRING INDEX: %v\n\n", pairing.Index()))
	return nil
}

func (s *shellRunner) commandKeycardUnpair(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	indexInt, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return err
	}
	if s.secrets == nil {
		return errors.New("cannot unpair without setting secrets")
	}
	if err := s.kc.Unpair(uint8(indexInt)); err != nil {
		return err
	}
	s.write("UNPAIRED\n\n")
	return nil
}

func (s *shellRunner) commandKeycardSetPairing(args ...string) error {
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
	var keyArr [32]byte
	copy(keyArr[:], key)
	s.kc.SetPairing(types.NewPairing(keyArr, uint8(index)))
	return nil
}

func (s *shellRunner) commandKeycardOpenSecureChannel(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	if s.kc.Pairing() == nil {
		return errors.New("cannot open secure channel without setting pairing info")
	}
	return s.kc.OpenSecureChannel()
}

func (s *shellRunner) commandKeycardGetStatus(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	appStatus, err := s.kc.GetStatusApplication()
	if err != nil {
		return err
	}
	keyStatus, err := s.kc.GetStatusKeyPath()
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("STATUS - PIN RETRY COUNT: %d\n", appStatus.PinRetryCount))
	s.write(fmt.Sprintf("STATUS - PUK RETRY COUNT: %d\n", appStatus.PUKRetryCount))
	s.write(fmt.Sprintf("STATUS - KEY INITIALIZED: %v\n", appStatus.KeyInitialized))
	s.write(fmt.Sprintf("STATUS - KEY PATH: %v\n\n", keyStatus.Path))
	return nil
}

func (s *shellRunner) commandKeycardVerifyPIN(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	return s.kc.VerifyPIN(args[0])
}

func (s *shellRunner) commandKeycardChangePIN(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	return s.kc.ChangePIN(args[0])
}

func (s *shellRunner) commandKeycardChangePUK(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	return s.kc.ChangePUK(args[0])
}

func (s *shellRunner) commandKeycardUnblockPin(args ...string) error {
	if err := s.requireArgs(args, 2); err != nil {
		return err
	}
	return s.kc.UnblockPIN(args[0], args[1])
}

func (s *shellRunner) commandKeycardChangePairingSecret(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	return s.kc.ChangePairingSecret(args[0])
}

func (s *shellRunner) commandKeycardGenerateKey(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	appStatus, err := s.kc.GetStatusApplication()
	if err != nil {
		return err
	}
	if appStatus.KeyInitialized {
		return errors.New("key already generated. You must delete it before creating a new one")
	}
	keyUID, err := s.kc.GenerateKey()
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("KEY UID %x\n\n", keyUID))
	return nil
}

func (s *shellRunner) commandKeycardRemoveKey(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	if err := s.kc.RemoveKey(); err != nil {
		return err
	}
	s.write("KEY REMOVED\n\n")
	return nil
}

func (s *shellRunner) commandKeycardDeriveKey(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	return s.kc.DeriveKey(args[0])
}

func (s *shellRunner) commandKeycardExportKeyPrivate(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	path := args[0]
	exported, err := s.kc.ExportKeyWithP2(false, false, keycard.P2ExportKeyPrivateAndPublic, path)
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("PRIVATE KEY: 0x%x\n", exported.PrivKey()))
	s.write(fmt.Sprintf("PUBLIC KEY: 0x%x\n\n", exported.PubKey()))
	return nil
}

func (s *shellRunner) commandKeycardExportKeyPublic(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	path := args[0]
	exported, err := s.kc.ExportKeyWithP2(false, false, keycard.P2ExportKeyPublicOnly, path)
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("PUBLIC KEY: 0x%x\n\n", exported.PubKey()))
	return nil
}

func (s *shellRunner) commandKeycardSign(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return err
	}
	sig, err := s.kc.Sign(data)
	if err != nil {
		return err
	}
	s.writeSignatureInfo(sig)
	return nil
}

func (s *shellRunner) commandKeycardSignWithPath(args ...string) error {
	if err := s.requireArgs(args, 2); err != nil {
		return err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return err
	}
	sig, err := s.kc.SignWithPath(data, args[1])
	if err != nil {
		return err
	}
	s.writeSignatureInfo(sig)
	return nil
}

func (s *shellRunner) commandKeycardSignMessage(args ...string) error {
	if len(args) < 1 {
		return errors.New("keycard-sign-message requires at least 1 parameter")
	}
	originalMessage := strings.Join(args, " ")
	hash := hashEthereumMessage(originalMessage)
	sig, err := s.kc.Sign(hash)
	if err != nil {
		return err
	}
	s.writeSignatureInfo(sig)
	return nil
}

func (s *shellRunner) commandKeycardSignPinless(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return err
	}
	sig, err := s.kc.SignPinless(data)
	if err != nil {
		return err
	}
	s.writeSignatureInfo(sig)
	return nil
}

func (s *shellRunner) commandKeycardSignMessagePinless(args ...string) error {
	if len(args) < 1 {
		return errors.New("keycard-sign-message-pinless requires at least 1 parameter")
	}
	originalMessage := strings.Join(args, " ")
	hash := hashEthereumMessage(originalMessage)
	sig, err := s.kc.SignPinless(hash)
	if err != nil {
		return err
	}
	s.writeSignatureInfo(sig)
	return nil
}

func (s *shellRunner) commandKeycardSetPinlessPath(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	return s.kc.SetPinlessPath(args[0])
}

func (s *shellRunner) commandKeycardGenerateMnemonic(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	checksumSize, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return err
	}
	indexes, err := s.kc.GenerateMnemonic(int(checksumSize))
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("MNEMONIC INDEXES %v\n\n", indexes))
	return nil
}

func (s *shellRunner) commandKeycardLoadSeed(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	seed, err := s.parseHex(args[0])
	if err != nil {
		return err
	}
	keyID, err := s.kc.LoadSeed(seed)
	if err != nil {
		return err
	}
	s.write(fmt.Sprintf("KEY ID %x\n\n", keyID))
	return nil
}

func (s *shellRunner) commandKeycardIdentify(args ...string) error {
	pubkey, err := s.kc.Identify()
	if err != nil {
		return err
	}
	var compareKey []byte
	if len(args) == 1 {
		compareKey, err = s.parseHex(args[0])
		if err != nil {
			return err
		}
	} else {
		compareKey = pubkey
	}
	if !bytes.Equal(compareKey, pubkey) {
		return errors.New("genuinity check failed")
	}
	s.write(fmt.Sprintf("IDENTIFICATION OK (public key: %x)\n\n", pubkey))
	return nil
}

func (s *shellRunner) commandCashSelect(args ...string) error {
	if err := s.requireArgs(args, 0); err != nil {
		return err
	}
	if err := s.cashKC.Select(); err != nil {
		return err
	}
	info := s.cashKC.CashApplicationInfo
	s.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	s.write(fmt.Sprintf("PublicKey: %x\n", info.PublicKey))
	s.write(fmt.Sprintf("Version: %x\n\n", info.Version))
	return nil
}

func (s *shellRunner) commandCashSign(args ...string) error {
	if err := s.requireArgs(args, 1); err != nil {
		return err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return err
	}
	sig, err := s.cashKC.Sign(data)
	if err != nil {
		return err
	}
	s.writeSignatureInfo(sig)
	return nil
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
