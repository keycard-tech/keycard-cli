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
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Output all results as a single JSON object at the end",
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
		return runShell(card, f, cmd.Bool("json"))
	}

	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return runShell(card, os.Stdin, cmd.Bool("json"))
	}

	return errors.New("non-interactive shell. You must pipe commands or use -f flag")
}

func runShell(card *scard.Card, input io.Reader, jsonOutput bool) error {
	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)
	cashKC := keycard.NewCashCommandSet(ch)
	gp := globalplatform.NewCommandSet(ch)

	shell := &shellRunner{
		ch:         ch,
		kc:         kc,
		cashKC:     cashKC,
		gp:         gp,
		out:        new(bytes.Buffer),
		jsonOutput: jsonOutput,
		results:    make(map[string]map[string]interface{}),
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

type shellCommand = func(args ...string) (map[string]interface{}, error)

type shellRunner struct {
	ch         types.Channel
	kc         *keycard.CommandSet
	cashKC     *keycard.CashCommandSet
	gp         *globalplatform.CommandSet
	secrets    *keycard.Secrets
	commands   map[string]shellCommand
	out        *bytes.Buffer
	jsonOutput bool
	results    map[string]map[string]interface{}
	resultIdx  int
}

func (s *shellRunner) write(str string) {
	s.out.WriteString(str)
}

func (s *shellRunner) flushOut() {
	if s.jsonOutput {
		// Output all collected results as JSON
		internal.PrintJSON(s.results)
	}
	io.Copy(os.Stdout, s.out)
}

func (s *shellRunner) recordResult(cmdName string, result map[string]interface{}) {
	if !s.jsonOutput {
		return
	}
	key := fmt.Sprintf("%s_%d", cmdName, s.resultIdx)
	s.resultIdx++
	s.results[key] = result
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
		result, err := cmd(parts[1:]...)
		if result != nil {
			s.recordResult(parts[0], result)
		}
		return err
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

func (s *shellRunner) writeSignatureInfo(sig *types.Signature) map[string]interface{} {
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

	return map[string]interface{}{
		"signature_r":     "0x" + hex.EncodeToString(sig.R()),
		"signature_s":     "0x" + hex.EncodeToString(sig.S()),
		"signature_v":     int(sig.V()),
		"eth_signature":   "0x" + hex.EncodeToString(ethSig),
		"public_key":      "0x" + hex.EncodeToString(sig.PubKey()),
		"address":         address.String(),
	}
}

// Shell command implementations (ported from old shell.go)
func (s *shellRunner) commandEcho(args ...string) (map[string]interface{}, error) {
	s.write(fmt.Sprintf("> %s\n", strings.Join(args, " ")))
	return nil, nil
}

func (s *shellRunner) commandGPSendAPDU(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	rawCmd, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	cmd, err := apdu.ParseCommand(rawCmd)
	if err != nil {
		return nil, err
	}
	var channel types.Channel
	if sc := s.gp.SecureChannel(); sc != nil {
		channel = sc
	} else {
		channel = s.gp.Channel()
	}
	resp, err := channel.Send(cmd)
	if err != nil {
		return nil, err
	}
	if resp.Sw != apdu.SwOK {
		return nil, apdu.NewErrBadResponse(resp.Sw, "unexpected response")
	}
	return map[string]interface{}{
		"sw":   fmt.Sprintf("0x%04x", resp.Sw),
		"data": "0x" + hex.EncodeToString(resp.Data),
	}, nil
}

func (s *shellRunner) commandGPSelect(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0, 1); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		if err := s.gp.Select(); err != nil {
			return nil, err
		}
		s.write("Selected ISD\n")
		return map[string]interface{}{"selected": "isd"}, nil
	}
	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	if err := s.gp.SelectAID(aid); err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("Selected AID: %s\n", args[0]))
	return map[string]interface{}{"selected_aid": args[0]}, nil
}

func (s *shellRunner) commandGPOpenSecureChannel(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if err := s.gp.OpenSecureChannel(); err != nil {
		return nil, err
	}
	s.write("GP secure channel opened\n")
	return map[string]interface{}{"secure_channel": "opened"}, nil
}

func (s *shellRunner) commandGPDelete(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	if err := s.gp.DeleteObject(aid); err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("Deleted AID: %s\n", args[0]))
	return map[string]interface{}{"deleted_aid": args[0]}, nil
}

func (s *shellRunner) commandGPLoad(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 2); err != nil {
		return nil, err
	}
	f, err := os.Open(args[0])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkgAID, err := hex.DecodeString(args[1])
	if err != nil {
		return nil, err
	}
	callback := func(index, total int) {}
	if err := s.gp.LoadPackage(f, pkgAID, callback); err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("Package loaded: %s\n", args[1]))
	return map[string]interface{}{"package_aid": args[1], "loaded": true}, nil
}

func (s *shellRunner) commandGPInstallForInstall(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 3, 4); err != nil {
		return nil, err
	}
	pkgAID, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	appletAID, err := hex.DecodeString(args[1])
	if err != nil {
		return nil, err
	}
	instanceAID, err := hex.DecodeString(args[2])
	if err != nil {
		return nil, err
	}
	var params []byte
	if len(args) == 4 {
		params, err = hex.DecodeString(args[3])
		if err != nil {
			return nil, err
		}
	}
	if err := s.gp.InstallForInstall(pkgAID, appletAID, instanceAID, params); err != nil {
		return nil, err
	}
	s.write("Install for install complete\n")
	return map[string]interface{}{
		"package_aid":  args[0],
		"applet_aid":   args[1],
		"instance_aid": args[2],
		"installed":    true,
	}, nil
}

func (s *shellRunner) commandGPGetStatus(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	cardStatus, err := s.gp.GetStatus()
	if err != nil {
		return nil, err
	}
	lifecycle := cardStatus.LifeCycle()
	s.write(fmt.Sprintf("CARD STATUS: %s\n\n", lifecycle))
	return map[string]interface{}{"lifecycle": lifecycle}, nil
}

func (s *shellRunner) commandKeycardInit(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if s.kc.AppInfo() == nil || !s.kc.AppInfo().Installed {
		return nil, errors.New("keycard applet not installed")
	}
	if s.kc.AppInfo().Initialized {
		return nil, errors.New("card already initialized")
	}
	if s.secrets == nil {
		secrets, err := keycard.GenerateSecrets()
		if err != nil {
			return nil, err
		}
		s.secrets = secrets
	}
	if err := s.kc.Init(s.secrets); err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("PIN: %s\n", s.secrets.Pin()))
	s.write(fmt.Sprintf("PUK: %s\n", s.secrets.Puk()))
	s.write(fmt.Sprintf("PAIRING PASSWORD: %s\n\n", s.secrets.PairingPass()))
	return map[string]interface{}{
		"pin":              s.secrets.Pin(),
		"puk":              s.secrets.Puk(),
		"pairing_password": s.secrets.PairingPass(),
	}, nil
}

func (s *shellRunner) commandKeycardSetSecrets(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 3); err != nil {
		return nil, err
	}
	s.secrets = keycard.NewSecrets(args[0], args[1], args[2])
	return map[string]interface{}{
		"pin":              args[0],
		"puk":              args[1],
		"pairing_password": args[2],
	}, nil
}

func (s *shellRunner) commandKeycardSelect(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if err := s.kc.Select(); err != nil {
		return nil, err
	}
	info := s.kc.AppInfo()
	s.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	s.write(fmt.Sprintf("Initialized: %v\n", info.Initialized))
	s.write(fmt.Sprintf("Key Initialized: %v\n", len(info.KeyUID) > 0))
	s.write(fmt.Sprintf("Version: %x\n", info.AppVersion()))
	s.write(fmt.Sprintf("KeyUID: %x\n\n", info.KeyUID))
	return map[string]interface{}{
		"installed":     info.Installed,
		"initialized":   info.Initialized,
		"key_uid":       "0x" + hex.EncodeToString(info.KeyUID),
		"app_version":   fmt.Sprintf("0x%04x", info.AppVersion()),
	}, nil
}

func (s *shellRunner) commandKeycardPair(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if s.secrets == nil {
		return nil, errors.New("cannot pair without setting secrets")
	}
	if err := s.kc.Pair(s.secrets.PairingPass()); err != nil {
		return nil, err
	}
	pairing := s.kc.Pairing()
	key := pairing.Key()
	s.write(fmt.Sprintf("PAIRING KEY: %x\n", key[:]))
	s.write(fmt.Sprintf("PAIRING INDEX: %v\n\n", pairing.Index()))
	return map[string]interface{}{
		"pairing_key":   fmt.Sprintf("0x%x", key[:]),
		"pairing_index": pairing.Index(),
	}, nil
}

func (s *shellRunner) commandKeycardUnpair(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	indexInt, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return nil, err
	}
	if s.secrets == nil {
		return nil, errors.New("cannot unpair without setting secrets")
	}
	if err := s.kc.Unpair(uint8(indexInt)); err != nil {
		return nil, err
	}
	s.write("UNPAIRED\n\n")
	return map[string]interface{}{"unpaired_index": int(indexInt)}, nil
}

func (s *shellRunner) commandKeycardSetPairing(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 2); err != nil {
		return nil, err
	}
	key, err := s.parseHex(args[0])
	if err != nil {
		return nil, err
	}
	index, err := strconv.ParseInt(args[1], 10, 8)
	if err != nil {
		return nil, err
	}
	var keyArr [32]byte
	copy(keyArr[:], key)
	s.kc.SetPairing(types.NewPairing(keyArr, uint8(index)))
	return map[string]interface{}{
		"pairing_key":   args[0],
		"pairing_index": int(index),
	}, nil
}

func (s *shellRunner) commandKeycardOpenSecureChannel(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if s.kc.Pairing() == nil {
		return nil, errors.New("cannot open secure channel without setting pairing info")
	}
	if err := s.kc.OpenSecureChannel(); err != nil {
		return nil, err
	}
	s.write("Secure channel opened\n")
	return map[string]interface{}{"secure_channel": "opened"}, nil
}

func (s *shellRunner) commandKeycardGetStatus(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	appStatus, err := s.kc.GetStatusApplication()
	if err != nil {
		return nil, err
	}
	keyStatus, err := s.kc.GetStatusKeyPath()
	if err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("STATUS - PIN RETRY COUNT: %d\n", appStatus.PinRetryCount))
	s.write(fmt.Sprintf("STATUS - PUK RETRY COUNT: %d\n", appStatus.PUKRetryCount))
	s.write(fmt.Sprintf("STATUS - KEY INITIALIZED: %v\n", appStatus.KeyInitialized))
	s.write(fmt.Sprintf("STATUS - KEY PATH: %v\n\n", keyStatus.Path))
	return map[string]interface{}{
		"pin_retry_count":  appStatus.PinRetryCount,
		"puk_retry_count":  appStatus.PUKRetryCount,
		"key_initialized":  appStatus.KeyInitialized,
		"key_path":         keyStatus.Path,
	}, nil
}

func (s *shellRunner) commandKeycardVerifyPIN(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := s.kc.VerifyPIN(args[0]); err != nil {
		return nil, err
	}
	s.write("PIN verified\n")
	return map[string]interface{}{"pin_verified": true}, nil
}

func (s *shellRunner) commandKeycardChangePIN(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := s.kc.ChangePIN(args[0]); err != nil {
		return nil, err
	}
	s.write("PIN changed\n")
	return map[string]interface{}{"pin_changed": true}, nil
}

func (s *shellRunner) commandKeycardChangePUK(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := s.kc.ChangePUK(args[0]); err != nil {
		return nil, err
	}
	s.write("PUK changed\n")
	return map[string]interface{}{"puk_changed": true}, nil
}

func (s *shellRunner) commandKeycardUnblockPin(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 2); err != nil {
		return nil, err
	}
	if err := s.kc.UnblockPIN(args[0], args[1]); err != nil {
		return nil, err
	}
	s.write("PIN unblocked\n")
	return map[string]interface{}{"pin_unblocked": true}, nil
}

func (s *shellRunner) commandKeycardChangePairingSecret(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := s.kc.ChangePairingSecret(args[0]); err != nil {
		return nil, err
	}
	s.write("Pairing secret changed\n")
	return map[string]interface{}{"pairing_secret_changed": true}, nil
}

func (s *shellRunner) commandKeycardGenerateKey(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	appStatus, err := s.kc.GetStatusApplication()
	if err != nil {
		return nil, err
	}
	if appStatus.KeyInitialized {
		return nil, errors.New("key already generated. You must delete it before creating a new one")
	}
	keyUID, err := s.kc.GenerateKey()
	if err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("KEY UID %x\n\n", keyUID))
	return map[string]interface{}{"key_uid": "0x" + hex.EncodeToString(keyUID)}, nil
}

func (s *shellRunner) commandKeycardRemoveKey(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if err := s.kc.RemoveKey(); err != nil {
		return nil, err
	}
	s.write("KEY REMOVED\n\n")
	return map[string]interface{}{"key_removed": true}, nil
}

func (s *shellRunner) commandKeycardDeriveKey(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := s.kc.DeriveKey(args[0]); err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("Key derived at path: %s\n", args[0]))
	return map[string]interface{}{"path": args[0], "derived": true}, nil
}

func (s *shellRunner) commandKeycardExportKeyPrivate(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	path := args[0]
	exported, err := s.kc.ExportKeyWithP2(false, false, keycard.P2ExportKeyPrivateAndPublic, path)
	if err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("PRIVATE KEY: 0x%x\n", exported.PrivKey()))
	s.write(fmt.Sprintf("PUBLIC KEY: 0x%x\n\n", exported.PubKey()))
	return map[string]interface{}{
		"private_key": "0x" + hex.EncodeToString(exported.PrivKey()),
		"public_key":  "0x" + hex.EncodeToString(exported.PubKey()),
		"path":        path,
	}, nil
}

func (s *shellRunner) commandKeycardExportKeyPublic(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	path := args[0]
	exported, err := s.kc.ExportKeyWithP2(false, false, keycard.P2ExportKeyPublicOnly, path)
	if err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("PUBLIC KEY: 0x%x\n\n", exported.PubKey()))
	return map[string]interface{}{
		"public_key": "0x" + hex.EncodeToString(exported.PubKey()),
		"path":       path,
	}, nil
}

func (s *shellRunner) commandKeycardSign(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := s.kc.Sign(data)
	if err != nil {
		return nil, err
	}
	return s.writeSignatureInfo(sig), nil
}

func (s *shellRunner) commandKeycardSignWithPath(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 2); err != nil {
		return nil, err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := s.kc.SignWithPath(data, args[1])
	if err != nil {
		return nil, err
	}
	result := s.writeSignatureInfo(sig)
	result["path"] = args[1]
	return result, nil
}

func (s *shellRunner) commandKeycardSignMessage(args ...string) (map[string]interface{}, error) {
	if len(args) < 1 {
		return nil, errors.New("keycard-sign-message requires at least 1 parameter")
	}
	originalMessage := strings.Join(args, " ")
	hash := shellHashEthereumMessage(originalMessage)
	sig, err := s.kc.Sign(hash)
	if err != nil {
		return nil, err
	}
	return s.writeSignatureInfo(sig), nil
}

func (s *shellRunner) commandKeycardSignPinless(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := s.kc.SignPinless(data)
	if err != nil {
		return nil, err
	}
	return s.writeSignatureInfo(sig), nil
}

func (s *shellRunner) commandKeycardSignMessagePinless(args ...string) (map[string]interface{}, error) {
	if len(args) < 1 {
		return nil, errors.New("keycard-sign-message-pinless requires at least 1 parameter")
	}
	originalMessage := strings.Join(args, " ")
	hash := shellHashEthereumMessage(originalMessage)
	sig, err := s.kc.SignPinless(hash)
	if err != nil {
		return nil, err
	}
	return s.writeSignatureInfo(sig), nil
}

func (s *shellRunner) commandKeycardSetPinlessPath(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := s.kc.SetPinlessPath(args[0]); err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("Pinless path set: %s\n", args[0]))
	return map[string]interface{}{"pinless_path": args[0]}, nil
}

func (s *shellRunner) commandKeycardGenerateMnemonic(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	checksumSize, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return nil, err
	}
	indexes, err := s.kc.GenerateMnemonic(int(checksumSize))
	if err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("MNEMONIC INDEXES %v\n\n", indexes))
	return map[string]interface{}{"mnemonic_indexes": indexes}, nil
}

func (s *shellRunner) commandKeycardLoadSeed(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	seed, err := s.parseHex(args[0])
	if err != nil {
		return nil, err
	}
	keyID, err := s.kc.LoadSeed(seed)
	if err != nil {
		return nil, err
	}
	s.write(fmt.Sprintf("KEY ID %x\n\n", keyID))
	return map[string]interface{}{"key_id": "0x" + hex.EncodeToString(keyID)}, nil
}

func (s *shellRunner) commandKeycardIdentify(args ...string) (map[string]interface{}, error) {
	pubkey, err := s.kc.Identify()
	if err != nil {
		return nil, err
	}
	var compareKey []byte
	if len(args) == 1 {
		compareKey, err = s.parseHex(args[0])
		if err != nil {
			return nil, err
		}
	} else {
		compareKey = pubkey
	}
	if !bytes.Equal(compareKey, pubkey) {
		return nil, errors.New("genuinity check failed")
	}
	s.write(fmt.Sprintf("IDENTIFICATION OK (public key: %x)\n\n", pubkey))
	return map[string]interface{}{
		"identified": true,
		"public_key": "0x" + hex.EncodeToString(pubkey),
	}, nil
}

func (s *shellRunner) commandCashSelect(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 0); err != nil {
		return nil, err
	}
	if err := s.cashKC.Select(); err != nil {
		return nil, err
	}
	info := s.cashKC.CashApplicationInfo
	s.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	s.write(fmt.Sprintf("PublicKey: %x\n", info.PublicKey))
	s.write(fmt.Sprintf("Version: %x\n\n", info.Version))
	return map[string]interface{}{
		"installed":   info.Installed,
		"public_key":  "0x" + hex.EncodeToString(info.PublicKey),
		"version":     "0x" + hex.EncodeToString(info.Version),
	}, nil
}

func (s *shellRunner) commandCashSign(args ...string) (map[string]interface{}, error) {
	if err := s.requireArgs(args, 1); err != nil {
		return nil, err
	}
	data, err := s.parseHex(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := s.cashKC.Sign(data)
	if err != nil {
		return nil, err
	}
	return s.writeSignatureInfo(sig), nil
}

func shellHashEthereumMessage(message string) []byte {
	data := []byte(message)
	if strings.HasPrefix(message, "0x") {
		if value, err := hex.DecodeString(message[2:]); err == nil {
			data = value
		}
	}
	wrappedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(wrappedMessage))
}
